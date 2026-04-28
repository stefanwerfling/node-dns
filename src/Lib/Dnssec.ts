import { Buffer } from 'buffer';
import * as crypto from 'crypto';
import {BufferWriter} from './BufferWriter.js';
import {PacketName} from '../Packet/PacketName.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {CNAME} from '../Packet/Types/CNAME.js';
import {DNAME} from '../Packet/Types/DNAME.js';
import {DNSKEY} from '../Packet/Types/DNSKEY.js';
import {DS} from '../Packet/Types/DS.js';
import {MX} from '../Packet/Types/MX.js';
import {NAPTR} from '../Packet/Types/NAPTR.js';
import {NS} from '../Packet/Types/NS.js';
import {NSEC} from '../Packet/Types/NSEC.js';
import {PTR} from '../Packet/Types/PTR.js';
import {RRSIG} from '../Packet/Types/RRSIG.js';
import {SOA} from '../Packet/Types/SOA.js';
import {SRV} from '../Packet/Types/SRV.js';

/**
 * IANA-registered DNSSEC Signing Algorithms (subset that we implement
 * verification for). Numbers are the wire-format codes used in DNSKEY,
 * RRSIG and DS records.
 *
 * @docs https://www.iana.org/assignments/dns-sec-alg-numbers
 */
export enum DnssecAlgorithm {
    RSASHA256 = 8,
    RSASHA512 = 10,
    ECDSAP256SHA256 = 13,
    ECDSAP384SHA384 = 14,
    ED25519 = 15,
}

/**
 * IANA DS digest types we support.
 *
 * @docs https://www.iana.org/assignments/ds-rr-types
 */
export enum DnssecDigest {
    SHA1 = 1,
    SHA256 = 2,
    SHA384 = 4,
}

/**
 * Options controlling RRSIG validity-window enforcement during verification.
 */
export type DnssecVerifyOptions = {
    /**
     * Override the "current time" used for the inception/expiration window
     * check (Unix seconds). Defaults to `Date.now() / 1000`.
     */
    now?: number;

    /**
     * Skip the RFC 4035 §5.3.1 inception/expiration window check. Useful
     * for replaying captured signatures or testing.
     */
    skipValidityWindow?: boolean;
};

/**
 * RFC 4034 / RFC 4035 verification primitives for DNSSEC. This layer is
 * deliberately stateless — there is no resolver, no cache, no chain
 * traversal. Callers feed in an RRset together with its RRSIG and a
 * candidate DNSKEY; the verifier returns a boolean.
 *
 * Scope (Phase 1):
 *   - `verifyRrsig` — check one RRSIG against one DNSKEY for one RRset.
 *     Algorithms 8, 10, 13, 14, 15.
 *   - `computeDsDigest` / `verifyDs` — DS-vs-DNSKEY hash check (digest
 *     types 1, 2, 4).
 *   - `computeKeyTag` — RFC 4034 Appendix B key tag.
 *
 * Out of scope here:
 *   - Wildcard label-count reconstruction (RFC 4034 §3.1.3).
 *   - NSEC/NSEC3 negative-answer proofs.
 *   - Walking the chain of trust from a trust anchor (root KSK) down to
 *     the queried name — that lives one layer up in the recursive
 *     resolver.
 */
export class Dnssec {

    /**
     * RR types whose RDATA contains no embedded domain names. For these
     * the wire-format encode of the type is already in canonical form
     * (RFC 4034 §6.2 step 2 only applies when names are embedded).
     * @protected
     */
    protected static readonly _RAW_CANONICAL_TYPES: ReadonlySet<number> = new Set([
        PacketTypes.A,
        PacketTypes.AAAA,
        PacketTypes.CAA,
        PacketTypes.DNSKEY,
        PacketTypes.DS,
        PacketTypes.NSEC3,
        PacketTypes.SPF,
        PacketTypes.SSHFP,
        PacketTypes.TLSA,
        PacketTypes.TXT,
    ]);

    /**
     * RFC 4034 Appendix B key tag computation. Not algorithm-specific —
     * the same 16-bit folded checksum across DNSKEY RDATA is used for all
     * algorithms (per the IANA registry there is no surviving key-tag
     * exception today).
     */
    public static computeKeyTag(dnskey: DNSKEY): number {
        const rdata = Dnssec._dnskeyRdataBytes(dnskey);
        let ac = 0;

        for (let i = 0; i < rdata.length; i++) {
            // eslint-disable-next-line no-bitwise
            ac += i & 1 ? rdata[i] : rdata[i] << 8;
        }

        // eslint-disable-next-line no-bitwise
        ac += (ac >> 16) & 0xFFFF;
        // eslint-disable-next-line no-bitwise
        return ac & 0xFFFF;
    }

    /**
     * RFC 4034 §5.1.4 DS digest:
     *
     *     digest = H(canonical_owner | DNSKEY_RDATA)
     *
     * where the owner name is in canonical form (lowercased,
     * uncompressed). Returned as lowercase hex matching `DS.digest`.
     */
    public static computeDsDigest(owner: string, dnskey: DNSKEY, digestType: number): string {
        const ownerBuf = Dnssec._canonicalNameBytes(owner);
        const dnskeyBuf = Dnssec._dnskeyRdataBytes(dnskey);
        const input = Buffer.concat([ownerBuf, dnskeyBuf]);
        const hashName = Dnssec._hashNameForDigest(digestType);

        return crypto.createHash(hashName).update(input).digest('hex');
    }

    /**
     * Convenience: compute the DS digest for `dnskey` and compare against
     * the `ds` record fields (algorithm, key tag, digest type, digest).
     */
    public static verifyDs(owner: string, dnskey: DNSKEY, ds: DS): boolean {
        if (ds.algorithm !== dnskey.algorithm) {
            return false;
        }

        if (Dnssec.computeKeyTag(dnskey) !== ds.keyTag) {
            return false;
        }

        const computed = Dnssec.computeDsDigest(owner, dnskey, ds.digestType);
        return computed.toLowerCase() === ds.digest.toLowerCase();
    }

    /**
     * Verify a single RRSIG against a single DNSKEY for an RRset.
     *
     * Returns true if and only if the signature decodes, the inception /
     * expiration window contains the current time (unless skipped), and
     * the cryptographic verification succeeds.
     *
     * Throws on internal errors (unsupported algorithm, malformed key,
     * unsupported RR type with embedded names) so callers can distinguish
     * "validation failed" from "we cannot judge".
     */
    public static verifyRrsig(
        owner: string,
        rrset: PacketResource[],
        rrsig: RRSIG,
        dnskey: DNSKEY,
        options: DnssecVerifyOptions = {}
    ): boolean {
        if (rrset.length === 0) {
            throw new Error('Dnssec.verifyRrsig: rrset is empty');
        }

        const rrType = rrset[0].packetType.type;

        if (rrsig.sigType !== rrType) {
            return false;
        }

        if (rrsig.algorithm !== dnskey.algorithm) {
            return false;
        }

        if (rrsig.keyTag !== Dnssec.computeKeyTag(dnskey)) {
            return false;
        }

        // RFC 4035 §5.3.1: the labels field must be ≤ the owner's label
        // count (excluding root). A larger value is a malformed signature.
        const ownerLabelCount = rrset[0].name.split('.').filter((l) => l.length > 0).length;

        if (rrsig.labels > ownerLabelCount) {
            return false;
        }

        if (options.skipValidityWindow !== true) {
            const now = options.now ?? Math.floor(Date.now() / 1000);
            const inception = Dnssec._parseSigDate(rrsig.inception);
            const expiration = Dnssec._parseSigDate(rrsig.expiration);

            if (now < inception || now > expiration) {
                return false;
            }
        }

        const input = Dnssec.buildSigningInput(owner, rrset, rrsig);
        const signature = Buffer.from(rrsig.signature, 'base64');

        return Dnssec._verifyAlgorithm(rrsig.algorithm, input, signature, dnskey);
    }

    /**
     * Construct the byte sequence that the signer hashed (RFC 4034 §3.1.8.1):
     *
     *     signed_data = RRSIG_RDATA(without sig) | RR(1) | RR(2) | …
     *
     * Each `RR(i)` is the canonical form of one record in the RRset:
     * canonical owner | type | class | RRSIG.originalTtl | rdlength |
     * canonical rdata. The records are sorted by canonical RDATA bytes.
     */
    public static buildSigningInput(
        owner: string,
        rrset: PacketResource[],
        rrsig: RRSIG
    ): Buffer {
        const sigHeader = Dnssec._rrsigSignedHeader(rrsig);
        const signedOwner = Dnssec._reconstructSignedOwner(owner, rrsig.labels);
        const ownerBuf = Dnssec._canonicalNameBytes(signedOwner);
        const rrType = rrset[0].packetType.type;
        const rrClass = rrset[0].class;

        const canonicalRdatas = rrset.map((rr) => Dnssec._canonicalRdataBytes(rr));
        canonicalRdatas.sort(Buffer.compare);

        const parts: Buffer[] = [sigHeader];

        for (const rdata of canonicalRdatas) {
            const fixed = Buffer.alloc(2 + 2 + 4 + 2);
            fixed.writeUInt16BE(rrType, 0);
            fixed.writeUInt16BE(rrClass, 2);
            fixed.writeUInt32BE(rrsig.originalTtl, 4);
            fixed.writeUInt16BE(rdata.length, 8);
            parts.push(ownerBuf, fixed, rdata);
        }

        return Buffer.concat(parts);
    }

    /**
     * RFC 4034 §6.1 canonical DNS name order. Returns -1, 0, or +1 when
     * `a` is respectively before, equal to, or after `b` in the
     * NSEC-chain ordering.
     *
     * Comparison is right-to-left, label-by-label: the rightmost label
     * (TLD) has the highest order. Within a label, octets are compared
     * as unsigned values after lowercasing the ASCII letters. A name
     * that is a strict suffix of another sorts first (parent < child).
     *
     * Useful for sorting NSEC chains and locating an NSEC RR that
     * covers a given query name.
     */
    public static canonicalNameCompare(a: string, b: string): number {
        const aLabels = a.toLowerCase().split('.').filter((l) => l.length > 0);
        const bLabels = b.toLowerCase().split('.').filter((l) => l.length > 0);

        const overlap = Math.min(aLabels.length, bLabels.length);

        for (let i = 0; i < overlap; i++) {
            const labelA = aLabels[aLabels.length - 1 - i];
            const labelB = bLabels[bLabels.length - 1 - i];
            const cmp = Buffer.compare(Buffer.from(labelA, 'utf8'), Buffer.from(labelB, 'utf8'));

            if (cmp !== 0) {
                return cmp < 0 ? -1 : 1;
            }
        }

        if (aLabels.length === bLabels.length) {
            return 0;
        }

        return aLabels.length < bLabels.length ? -1 : 1;
    }

    /**
     * Does an NSEC RR at `ownerName` with `nextDomain` prove that
     * `queryName` does not exist? RFC 4035 §5.4 NSEC name-error proof
     * needs `ownerName < queryName < nextDomain` in canonical order.
     *
     * Wrap-around case: at the end of the zone, the last NSEC's
     * `nextDomain` points back to the apex, so `nextDomain ≤ ownerName`
     * canonically. In that case, `queryName` is covered if it sorts
     * after `ownerName` OR strictly before `nextDomain` — i.e. it falls
     * into the "tail" of the chain.
     */
    public static nsecCovers(ownerName: string, nextDomain: string, queryName: string): boolean {
        const ownerVsQuery = Dnssec.canonicalNameCompare(ownerName, queryName);
        const queryVsNext = Dnssec.canonicalNameCompare(queryName, nextDomain);
        const ownerVsNext = Dnssec.canonicalNameCompare(ownerName, nextDomain);

        if (ownerVsNext < 0) {
            // Normal range: owner < next, query must be strictly between.
            return ownerVsQuery < 0 && queryVsNext < 0;
        }

        // Wrap-around (last NSEC in the chain): owner ≥ next.
        // queryName is covered if it's strictly after owner OR strictly
        // before next.
        return ownerVsQuery < 0 || queryVsNext < 0;
    }

    /**
     * RFC 5155 §5 NSEC3 hash. Per RFC 9276, only algorithm 1 (SHA-1) is
     * defined for production; any other value throws.
     *
     * The "iterations" field counts *additional* hash rounds beyond the
     * first, so iterations=0 → 1 SHA-1 call, iterations=N → N+1 calls.
     *
     * Returns the raw 20-byte hash. Use `base32hexEncode` to turn it
     * into the label that NSEC3 owner names use.
     */
    public static nsec3Hash(
        name: string,
        saltHex: string,
        iterations: number,
        algorithm: number = 1
    ): Buffer {
        if (algorithm !== 1) {
            throw new Error(
                `Dnssec: unsupported NSEC3 hash algorithm ${algorithm} (RFC 9276: only SHA-1 = 1 is allowed)`
            );
        }

        const salt = saltHex.length > 0 ? Buffer.from(saltHex, 'hex') : Buffer.alloc(0);
        const nameBuf = Dnssec._canonicalNameBytes(name);

        let hash = crypto.createHash('sha1').update(nameBuf).update(salt).digest();

        for (let i = 0; i < iterations; i++) {
            hash = crypto.createHash('sha1').update(hash).update(salt).digest();
        }

        return hash;
    }

    /**
     * Does an NSEC3 RR with `ownerHash` (the hashed first label of its
     * owner name) and `nextHash` (the wire-format Next Hashed Owner)
     * cover `queryHash`?
     *
     * Same wrap-around logic as `nsecCovers`, but on raw hash bytes
     * compared as unsigned big-endian integers (`Buffer.compare`).
     */
    public static nsec3CoversHash(ownerHash: Buffer, nextHash: Buffer, queryHash: Buffer): boolean {
        const ownerVsQuery = Buffer.compare(ownerHash, queryHash);
        const queryVsNext = Buffer.compare(queryHash, nextHash);
        const ownerVsNext = Buffer.compare(ownerHash, nextHash);

        if (ownerVsNext < 0) {
            return ownerVsQuery < 0 && queryVsNext < 0;
        }

        return ownerVsQuery < 0 || queryVsNext < 0;
    }

    /**
     * RFC 4648 §7 base32hex (extended hex alphabet, no padding).
     * Used to render an NSEC3 hash as the first label of a hashed
     * owner name (`<base32hex(hash)>.<zone>`).
     */
    public static base32hexEncode(buf: Buffer): string {
        const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
        let value = 0;
        let bits = 0;
        let result = '';

        for (const byte of buf) {
            // eslint-disable-next-line no-bitwise
            value = (value << 8) | byte;
            bits += 8;

            while (bits >= 5) {
                bits -= 5;
                // eslint-disable-next-line no-bitwise
                result += alphabet[(value >>> bits) & 0x1F];
                // Drop the bits we just emitted so `value` stays bounded
                // and 32-bit-arithmetic-safe.
                // eslint-disable-next-line no-bitwise
                value &= (1 << bits) - 1;
            }
        }

        if (bits > 0) {
            // eslint-disable-next-line no-bitwise
            result += alphabet[(value << (5 - bits)) & 0x1F];
        }

        return result;
    }

    /**
     * RFC 4034 §3.1.3: when `rrsig.labels` is less than the actual label
     * count of `owner` (root and any leading wildcard label excluded), the
     * authoritative server expanded a wildcard. The signer's input used
     * `*.<trailing labels>` rather than the expanded owner, so the
     * verifier has to reconstruct the same name before hashing.
     *
     * If `rrsig.labels` matches the owner's label count, the owner is
     * returned unchanged.
     * @protected
     */
    protected static _reconstructSignedOwner(owner: string, signerLabels: number): string {
        const ownerLabels = owner.split('.').filter((l) => l.length > 0);

        if (signerLabels >= ownerLabels.length) {
            return owner;
        }

        const trailing = ownerLabels.slice(ownerLabels.length - signerLabels);
        return `*.${trailing.join('.')}`;
    }

    /**
     * Build the RRSIG_RDATA portion that is signed: same as the wire
     * RDATA but without the trailing signature field. The signer name is
     * lowercased per RFC 4034 §6.2 and emitted uncompressed.
     * @protected
     */
    protected static _rrsigSignedHeader(rrsig: RRSIG): Buffer {
        const w = new BufferWriter();
        w.write(rrsig.sigType, 16);
        w.write(rrsig.algorithm, 8);
        w.write(rrsig.labels, 8);
        w.write(rrsig.originalTtl, 32);
        w.write(Dnssec._parseSigDate(rrsig.expiration), 32);
        w.write(Dnssec._parseSigDate(rrsig.inception), 32);
        w.write(rrsig.keyTag, 16);
        PacketName.encode(rrsig.signer.toLowerCase(), w);

        return w.toBuffer();
    }

    /**
     * Encode an owner name in canonical form: lowercased, uncompressed
     * length-prefixed labels, null-terminated.
     * @protected
     */
    protected static _canonicalNameBytes(name: string): Buffer {
        const w = new BufferWriter();
        PacketName.encode(name.toLowerCase(), w);
        return w.toBuffer();
    }

    /**
     * Canonical RDATA for one record per RFC 4034 §6.2: types whose RDATA
     * holds no domain names use their wire-format encode as-is; types with
     * embedded names re-emit them lowercased and uncompressed.
     *
     * Multi-name types (SOA, SRV, NAPTR, NSEC, RRSIG) are handled by
     * cloning the record with lowercased name fields and calling the
     * existing `encode` — the type's own encode already builds RDATA in a
     * fresh writer, so no compression leaks in.
     * @protected
     */
    protected static _canonicalRdataBytes(resource: PacketResource): Buffer {
        const pt = resource.packetType;

        if (Dnssec._RAW_CANONICAL_TYPES.has(pt.type)) {
            return pt.encode(resource).subarray(2);
        }

        const w = new BufferWriter();

        switch (pt.type) {
            case PacketTypes.NS:
                PacketName.encode((pt as NS).ns.toLowerCase(), w);
                return w.toBuffer();

            case PacketTypes.CNAME:
                PacketName.encode((pt as CNAME).domain.toLowerCase(), w);
                return w.toBuffer();

            case PacketTypes.DNAME:
                PacketName.encode((pt as DNAME).target.toLowerCase(), w);
                return w.toBuffer();

            case PacketTypes.PTR:
                PacketName.encode((pt as PTR).domain.toLowerCase(), w);
                return w.toBuffer();

            case PacketTypes.MX: {
                const mx = pt as MX;
                w.write(mx.priority, 16);
                PacketName.encode(mx.exchange.toLowerCase(), w);
                return w.toBuffer();
            }

            case PacketTypes.SOA: {
                const soa = pt as SOA;
                const lowered = new SOA(
                    soa.primary.toLowerCase(),
                    soa.admin.toLowerCase(),
                    soa.serial,
                    soa.refresh,
                    soa.retry,
                    soa.expiration,
                    soa.minimum
                );
                return lowered.encode({} as PacketResource).subarray(2);
            }

            case PacketTypes.SRV: {
                const srv = pt as SRV;
                const lowered = new SRV(
                    srv.priority,
                    srv.weight,
                    srv.port,
                    srv.target.toLowerCase()
                );
                return lowered.encode({} as PacketResource).subarray(2);
            }

            case PacketTypes.NAPTR: {
                // RFC 4034 §6.2 step 2 lowercases only the embedded *name*
                // (replacement). The flags/services/regexp character-strings
                // are not subject to case canonicalization.
                const naptr = pt as NAPTR;
                const lowered = new NAPTR(
                    naptr.order,
                    naptr.preference,
                    naptr.flags,
                    naptr.services,
                    naptr.regexp,
                    naptr.replacement.toLowerCase()
                );
                return lowered.encode({} as PacketResource).subarray(2);
            }

            case PacketTypes.NSEC: {
                const nsec = pt as NSEC;
                const lowered = new NSEC(nsec.nextDomain.toLowerCase(), nsec.rdtypes);
                return lowered.encode({} as PacketResource).subarray(2);
            }

            case PacketTypes.RRSIG: {
                // Canonical RDATA for an RRSIG keeps the signature bytes
                // untouched; only the embedded signer name is lowercased.
                // (Signing an RRSIG with another RRSIG is unusual but
                // allowed.)
                const rr = pt as RRSIG;
                const lowered = new RRSIG(
                    rr.sigType,
                    rr.algorithm,
                    rr.labels,
                    rr.originalTtl,
                    rr.expiration,
                    rr.inception,
                    rr.keyTag,
                    rr.signer.toLowerCase(),
                    rr.signature
                );
                return lowered.encode({} as PacketResource).subarray(2);
            }

            default:
                throw new Error(
                    `Dnssec: canonical RDATA for type ${pt.type} is not implemented — ` +
                    'please add a case if your zone needs it'
                );
        }
    }

    /**
     * Re-emit a DNSKEY's RDATA so we can hash it for DS / key-tag work.
     * `DNSKEY.encode` returns `rdlength | rdata`; strip the leading 2-byte
     * length.
     * @protected
     */
    protected static _dnskeyRdataBytes(dnskey: DNSKEY): Buffer {
        const wire = dnskey.encode({} as PacketResource);
        return wire.subarray(2);
    }

    /**
     * Map a DS digest type to the Node `crypto.createHash` algorithm name.
     * @protected
     */
    protected static _hashNameForDigest(digestType: number): string {
        switch (digestType) {
            case DnssecDigest.SHA1:
                return 'sha1';
            case DnssecDigest.SHA256:
                return 'sha256';
            case DnssecDigest.SHA384:
                return 'sha384';
            default:
                throw new Error(`Dnssec: unsupported DS digest type ${digestType}`);
        }
    }

    /**
     * RFC 4034 §3.2 presentation form: either an unsigned-decimal Unix
     * timestamp or a 14-character `YYYYMMDDHHMMSS` UTC string. Returns
     * the seconds-since-epoch wire value.
     * @protected
     */
    protected static _parseSigDate(value: string): number {
        if (/^\d+$/.test(value) && value.length !== 14) {
            return parseInt(value, 10);
        }

        if (!/^\d{14}$/.test(value)) {
            throw new Error(`Dnssec: invalid RRSIG date "${value}"`);
        }

        const year = parseInt(value.slice(0, 4), 10);
        const month = parseInt(value.slice(4, 6), 10);
        const day = parseInt(value.slice(6, 8), 10);
        const hour = parseInt(value.slice(8, 10), 10);
        const minute = parseInt(value.slice(10, 12), 10);
        const second = parseInt(value.slice(12, 14), 10);

        return Math.floor(Date.UTC(year, month - 1, day, hour, minute, second) / 1000);
    }

    /**
     * Dispatch to the algorithm-specific Node `crypto.verify` invocation.
     * @protected
     */
    protected static _verifyAlgorithm(
        algorithm: number,
        input: Buffer,
        signature: Buffer,
        dnskey: DNSKEY
    ): boolean {
        switch (algorithm) {
            case DnssecAlgorithm.RSASHA256:
                return crypto.verify(
                    'sha256',
                    input,
                    Dnssec._rsaPublicKey(dnskey),
                    signature
                );

            case DnssecAlgorithm.RSASHA512:
                return crypto.verify(
                    'sha512',
                    input,
                    Dnssec._rsaPublicKey(dnskey),
                    signature
                );

            case DnssecAlgorithm.ECDSAP256SHA256:
                return crypto.verify(
                    'sha256',
                    input,
                    {key: Dnssec._ecdsaPublicKey(dnskey, 32, 'P-256'), dsaEncoding: 'ieee-p1363'},
                    signature
                );

            case DnssecAlgorithm.ECDSAP384SHA384:
                return crypto.verify(
                    'sha384',
                    input,
                    {key: Dnssec._ecdsaPublicKey(dnskey, 48, 'P-384'), dsaEncoding: 'ieee-p1363'},
                    signature
                );

            case DnssecAlgorithm.ED25519:
                return crypto.verify(
                    null,
                    input,
                    Dnssec._ed25519PublicKey(dnskey),
                    signature
                );

            default:
                throw new Error(`Dnssec: unsupported algorithm ${algorithm}`);
        }
    }

    /**
     * Build a Node `KeyObject` from a DNSKEY whose key field is RFC 3110
     * RSA: `[explen | exp | mod]` where `explen` is either a single byte
     * (1-255) or a leading 0 byte followed by a uint16.
     * @protected
     */
    protected static _rsaPublicKey(dnskey: DNSKEY): crypto.KeyObject {
        const rdata = Buffer.from(dnskey.key, 'base64');

        if (rdata.length < 2) {
            throw new Error('Dnssec: RSA DNSKEY too short');
        }

        let off: number;
        let explen: number;

        if (rdata[0] === 0) {
            if (rdata.length < 3) {
                throw new Error('Dnssec: RSA DNSKEY truncated explen');
            }

            explen = rdata.readUInt16BE(1);
            off = 3;
        } else {
            explen = rdata[0];
            off = 1;
        }

        if (off + explen >= rdata.length) {
            throw new Error('Dnssec: RSA DNSKEY truncated key body');
        }

        const exponent = rdata.subarray(off, off + explen);
        const modulus = rdata.subarray(off + explen);

        const jwk: crypto.JsonWebKey = {
            kty: 'RSA',
            n: modulus.toString('base64url'),
            e: exponent.toString('base64url'),
        };

        return crypto.createPublicKey({key: jwk, format: 'jwk'});
    }

    /**
     * Build a Node `KeyObject` from an ECDSA DNSKEY. The key field is the
     * raw uncompressed point `X || Y` of length `2 * curveBytes`.
     * @protected
     */
    protected static _ecdsaPublicKey(
        dnskey: DNSKEY,
        curveBytes: number,
        jwkCurve: 'P-256' | 'P-384'
    ): crypto.KeyObject {
        const rdata = Buffer.from(dnskey.key, 'base64');

        if (rdata.length !== curveBytes * 2) {
            throw new Error(
                `Dnssec: ECDSA ${jwkCurve} DNSKEY must be ${curveBytes * 2} bytes, got ${rdata.length}`
            );
        }

        const jwk: crypto.JsonWebKey = {
            kty: 'EC',
            crv: jwkCurve,
            x: rdata.subarray(0, curveBytes).toString('base64url'),
            y: rdata.subarray(curveBytes).toString('base64url'),
        };

        return crypto.createPublicKey({key: jwk, format: 'jwk'});
    }

    /**
     * Build a Node `KeyObject` from an Ed25519 DNSKEY. The key field is
     * the 32-byte raw public key.
     * @protected
     */
    protected static _ed25519PublicKey(dnskey: DNSKEY): crypto.KeyObject {
        const rdata = Buffer.from(dnskey.key, 'base64');

        if (rdata.length !== 32) {
            throw new Error(
                `Dnssec: Ed25519 DNSKEY must be 32 bytes, got ${rdata.length}`
            );
        }

        const jwk: crypto.JsonWebKey = {
            kty: 'OKP',
            crv: 'Ed25519',
            x: rdata.toString('base64url'),
        };

        return crypto.createPublicKey({key: jwk, format: 'jwk'});
    }

}