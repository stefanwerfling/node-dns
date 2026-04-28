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
import {NSEC3} from '../Packet/Types/NSEC3.js';
import {NSEC3PARAM} from '../Packet/Types/NSEC3PARAM.js';
import {PTR} from '../Packet/Types/PTR.js';
import {RRSIG} from '../Packet/Types/RRSIG.js';
import {SOA} from '../Packet/Types/SOA.js';
import {SRV} from '../Packet/Types/SRV.js';
import {Zone} from '../Packet/Zone.js';

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
 * Options for `Dnssec.signRrset`.
 *
 * Inception / expiration accept either an RFC 4034 §3.2
 * `YYYYMMDDHHMMSS` UTC string or a unix-decimal seconds string / number.
 * Whatever the caller passes is normalized to the YYYYMMDDHHMMSS form on
 * the returned RRSIG.
 */
export type DnssecSignOptions = {
    /** Signature inception. */
    inception: string | number;

    /** Signature expiration. */
    expiration: string | number;

    /**
     * `originalTtl` to put on the RRSIG. Defaults to the TTL of the
     * first record in the RRset.
     */
    originalTtl?: number;

    /**
     * Signer name to put on the RRSIG. Defaults to the `owner` argument.
     */
    signer?: string;

    /**
     * Number of labels in the original (pre-wildcard-expansion) owner
     * name (RFC 4034 §3.1.3). Defaults to the non-empty label count of
     * `owner`, with a leading `*` skipped automatically.
     */
    labels?: number;
};

/**
 * One signing key bundle for `Dnssec.signZone`.
 */
export type DnssecZoneSigner = {
    /**
     * DNSKEY published in the zone for this signer.
     */
    dnskey: DNSKEY;

    /**
     * Matching Node `KeyObject` private key.
     */
    privateKey: crypto.KeyObject;
};

/**
 * Options for `Dnssec.signZone`.
 *
 * `ksk` and `zsk` may reference the same `DNSKEY`/`KeyObject` pair —
 * that's the CSK ("combined signing key") configuration that small
 * zones often use. Otherwise they are independent: KSK signs only the
 * DNSKEY RRset, ZSK signs every other RRset.
 */
export type DnssecSignZoneOptions = {
    /** Key-signing key. Signs the DNSKEY RRset. */
    ksk: DnssecZoneSigner;

    /** Zone-signing key. Signs every non-DNSKEY RRset. */
    zsk: DnssecZoneSigner;

    /** Signature inception, same format as `signRrset`. */
    inception: string | number;

    /** Signature expiration, same format as `signRrset`. */
    expiration: string | number;

    /**
     * TTL to use for the synthesized DNSKEY records. Defaults to the
     * zone's SOA minimum, falling back to 3600 if the zone has no SOA.
     */
    dnskeyTtl?: number;

    /**
     * Generate an NSEC chain (RFC 4034 §4) covering every owner name in
     * the zone. Each NSEC RR's NextDomain points to the canonically
     * next owner; the last entry wraps back to the apex. Every name's
     * type bit map includes the types actually present at that name
     * plus RRSIG and NSEC. The NSEC RRsets themselves are signed with
     * the ZSK like any other RRset.
     *
     * Without this flag, negative-answer validation against the signed
     * zone won't work — only positive answers verify.
     *
     * Mutually exclusive with `nsec3`.
     */
    nsec?: boolean;

    /**
     * Generate an NSEC3 chain (RFC 5155) instead of an NSEC chain. Each
     * unique owner name is hashed with the configured salt + iterations,
     * the hashes are sorted, and one NSEC3 RR is emitted per hash with
     * `nextHashedOwner` pointing to the next entry (wrapping at the
     * tail). An NSEC3PARAM RR is added at the apex publishing the same
     * parameters.
     *
     * Defaults follow RFC 9276: salt empty, iterations 0, opt-out off.
     * Mutually exclusive with `nsec`.
     */
    nsec3?: {
        /** Hex-encoded salt; empty string means "no salt". Default: ''. */
        salt?: string;

        /** Additional hash rounds beyond the first SHA-1. Default: 0. */
        iterations?: number;

        /** RFC 5155 §6 opt-out flag (set in every NSEC3 RR). Default: false. */
        optOut?: boolean;
    };
};

/**
 * Result of `Dnssec.signZone`.
 */
export type DnssecSignZoneResult = {
    /**
     * Every record that should be served as part of the signed zone:
     * the original zone records plus the synthesized DNSKEY RRset at
     * the apex.
     */
    records: PacketResource[];

    /**
     * RRSIG records covering every RRset in `records`. The DNSKEY RRset
     * is signed with the KSK; everything else is signed with the ZSK
     * (or both, if `ksk === zsk`, which is the CSK case).
     */
    rrsigs: PacketResource[];
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
        PacketTypes.CDNSKEY,
        PacketTypes.CDS,
        PacketTypes.DNSKEY,
        PacketTypes.DS,
        PacketTypes.NSEC3,
        PacketTypes.NSEC3PARAM,
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
     * Sign an RRset and return a complete RRSIG. The signing input is
     * built with the same canonical-form construction the verifier uses
     * (`buildSigningInput`), so a `signRrset` output round-trips through
     * `verifyRrsig` by construction.
     *
     * `dnskey` provides the algorithm and the key tag; `privateKey` is
     * the matching Node `KeyObject`. Defaults: `signer` = `owner`,
     * `originalTtl` = first record's TTL, `labels` = non-empty label
     * count of `owner`.
     */
    public static signRrset(
        owner: string,
        rrset: PacketResource[],
        dnskey: DNSKEY,
        privateKey: crypto.KeyObject,
        options: DnssecSignOptions
    ): RRSIG {
        if (rrset.length === 0) {
            throw new Error('Dnssec.signRrset: rrset is empty');
        }

        const inception = Dnssec._normalizeSigDate(options.inception);
        const expiration = Dnssec._normalizeSigDate(options.expiration);

        // RFC 4034 §3.1.3: a leading `*` wildcard label is not counted.
        const ownerLabels = owner.split('.').filter((l) => l.length > 0);
        const wildcardOffset = ownerLabels[0] === '*' ? 1 : 0;
        const labels = options.labels ?? (ownerLabels.length - wildcardOffset);

        const rrsig = new RRSIG(
            rrset[0].packetType.type,
            dnskey.algorithm,
            labels,
            options.originalTtl ?? rrset[0].ttl,
            expiration,
            inception,
            Dnssec.computeKeyTag(dnskey),
            options.signer ?? owner,
            ''
        );

        const input = Dnssec.buildSigningInput(owner, rrset, rrsig);
        const signature = Dnssec._signWithAlgorithm(dnskey.algorithm, input, privateKey);
        rrsig.signature = signature.toString('base64');

        return rrsig;
    }

    /**
     * Sign every RRset in a zone and synthesize the apex DNSKEY RRset.
     *
     * Returns the records that should be served (originals + DNSKEYs)
     * plus a parallel array of RRSIGs covering each RRset. The KSK
     * signs the DNSKEY RRset; the ZSK signs everything else. For a CSK
     * setup, pass the same key pair as both `ksk` and `zsk` — the
     * function picks up that they're the same and emits one signature
     * per RRset.
     *
     * Wildcard owners (e.g. `*.example.com`) are signed correctly:
     * `signRrset`'s default skips the leading `*` from the labels
     * field, so the verifier under any expanded query name
     * reconstructs the wildcard form before hashing.
     *
     * What this does **not** do (yet):
     *   - Generate the NSEC / NSEC3 chain. Negative answers from the
     *     resulting zone won't validate without those records.
     *   - Distinguish "key signing" from "zone signing" beyond the
     *     KSK/ZSK split. RFC 4034 §2.1.1 SEP-bit conventions are the
     *     caller's responsibility (typically: `flags = 257` for KSK,
     *     `flags = 256` for ZSK).
     */
    public static signZone(zone: Zone, options: DnssecSignZoneOptions): DnssecSignZoneResult {
        const apex = zone.origin.endsWith('.') ? zone.origin.slice(0, -1) : zone.origin;
        const apexLower = apex.toLowerCase();

        const dnskeyTtl = options.dnskeyTtl ?? Dnssec._defaultDnskeyTtl(zone);
        const cls = zone.records.length > 0 ? zone.records[0].class : 1; /* IN */
        const sameKey = options.ksk.dnskey === options.zsk.dnskey;

        const dnskeyRRs: PacketResource[] = [];
        dnskeyRRs.push(new PacketResource(apex, options.ksk.dnskey, cls, dnskeyTtl));

        if (!sameKey) {
            dnskeyRRs.push(new PacketResource(apex, options.zsk.dnskey, cls, dnskeyTtl));
        }

        if (options.nsec === true && options.nsec3 !== undefined) {
            throw new Error('Dnssec.signZone: `nsec` and `nsec3` are mutually exclusive');
        }

        let records: PacketResource[] = [...zone.records, ...dnskeyRRs];

        if (options.nsec === true) {
            const nsecRRs = Dnssec._generateNsecChain(records, cls, dnskeyTtl);
            records = [...records, ...nsecRRs];
        } else if (options.nsec3 !== undefined) {
            const nsec3RRs = Dnssec._generateNsec3Chain(
                records,
                apex,
                cls,
                dnskeyTtl,
                options.nsec3
            );
            records = [...records, ...nsec3RRs];
        }

        const rrsigs: PacketResource[] = [];

        // Group records by (lowercased owner name, type) so canonical
        // form differences in case don't split a single RRset.
        const groups = new Map<string, PacketResource[]>();

        for (const rr of records) {
            const key = `${rr.name.toLowerCase()}/${rr.packetType.type}`;
            const existing = groups.get(key);

            if (existing) {
                existing.push(rr);
            } else {
                groups.set(key, [rr]);
            }
        }

        for (const group of groups.values()) {
            const owner = group[0].name;
            const isApexDnskey =
                group[0].packetType.type === PacketTypes.DNSKEY
                && owner.toLowerCase() === apexLower;

            const signer = isApexDnskey ? options.ksk : options.zsk;

            const rrsig = Dnssec.signRrset(owner, group, signer.dnskey, signer.privateKey, {
                inception: options.inception,
                expiration: options.expiration,
                originalTtl: group[0].ttl,
                signer: apex,
            });

            rrsigs.push(new PacketResource(owner, rrsig, group[0].class, group[0].ttl));
        }

        return {records: records, rrsigs: rrsigs};
    }

    /**
     * RFC 4034 §4 NSEC chain generator. Walks `records`, collects the
     * set of types present at each owner name, lower-cases the names
     * for canonical comparison, sorts canonically, and emits one NSEC
     * RR per name pointing to the next in the chain. The last NSEC
     * wraps back to the first (the zone apex).
     *
     * Every name's type bit map includes the types actually present at
     * that name plus RRSIG and NSEC — the NSEC RRset itself will exist
     * after this call returns, and `signZone` will sign every RRset
     * (so RRSIG is universally present too).
     * @protected
     */
    protected static _generateNsecChain(
        records: PacketResource[],
        cls: number,
        ttl: number
    ): PacketResource[] {
        const nameToTypes = new Map<string, Set<number>>();

        for (const rr of records) {
            const lower = rr.name.toLowerCase();
            let types = nameToTypes.get(lower);

            if (!types) {
                types = new Set<number>();
                nameToTypes.set(lower, types);
            }

            types.add(rr.packetType.type);
        }

        for (const types of nameToTypes.values()) {
            types.add(PacketTypes.RRSIG);
            types.add(PacketTypes.NSEC);
        }

        const sortedNames = [...nameToTypes.keys()].sort(Dnssec.canonicalNameCompare);
        const result: PacketResource[] = [];

        for (let i = 0; i < sortedNames.length; i++) {
            const name = sortedNames[i];
            const next = sortedNames[(i + 1) % sortedNames.length];
            const types = [...nameToTypes.get(name)!].sort((a, b) => a - b);
            const nsec = new NSEC(next, types);
            result.push(new PacketResource(name, nsec, cls, ttl));
        }

        return result;
    }

    /**
     * RFC 5155 NSEC3 chain generator. Hashes every unique owner name
     * with the configured salt + iterations, sorts by hash, then emits
     * one NSEC3 RR per hash with the bitmap describing the types
     * present at the *original* (unhashed) owner. The last NSEC3 wraps
     * back to the first hash. An NSEC3PARAM RR is added at the apex
     * publishing the same parameters so validating resolvers know how
     * to hash their query names.
     *
     * Defaults (RFC 9276 §3.1): salt empty, iterations 0, opt-out off.
     * The opt-out flag, when set, propagates into every NSEC3 RR's
     * flags byte, but this generator does not actually skip insecure
     * delegations from the chain — it just publishes the flag.
     * @protected
     */
    protected static _generateNsec3Chain(
        records: PacketResource[],
        apex: string,
        cls: number,
        ttl: number,
        nsec3Options: {salt?: string; iterations?: number; optOut?: boolean}
    ): PacketResource[] {
        const salt = nsec3Options.salt ?? '';
        const iterations = nsec3Options.iterations ?? 0;
        const optOut = nsec3Options.optOut === true;
        const flags = optOut ? 1 : 0;
        const apexLower = apex.toLowerCase();

        const nameToTypes = new Map<string, Set<number>>();

        for (const rr of records) {
            const lower = rr.name.toLowerCase();
            let types = nameToTypes.get(lower);

            if (!types) {
                types = new Set<number>();
                nameToTypes.set(lower, types);
            }

            types.add(rr.packetType.type);
        }

        // Every original name will have at least one RRSIG once signing
        // completes; the bitmap reflects that.
        for (const types of nameToTypes.values()) {
            types.add(PacketTypes.RRSIG);
        }

        type Entry = {hashHex: string; types: number[]};
        const entries: Entry[] = [];

        for (const [name, types] of nameToTypes.entries()) {
            const hash = Dnssec.nsec3Hash(name, salt, iterations);
            entries.push({
                hashHex: hash.toString('hex'),
                types: [...types].sort((a, b) => a - b),
            });
        }

        entries.sort((a, b) =>
            Buffer.compare(Buffer.from(a.hashHex, 'hex'), Buffer.from(b.hashHex, 'hex'))
        );

        const result: PacketResource[] = [];

        for (let i = 0; i < entries.length; i++) {
            const cur = entries[i];
            const next = entries[(i + 1) % entries.length];
            const ownerLabel = Dnssec.base32hexEncode(Buffer.from(cur.hashHex, 'hex')).toLowerCase();
            const ownerName = `${ownerLabel}.${apexLower}`;
            const nsec3 = new NSEC3(
                1,
                flags,
                iterations,
                salt,
                next.hashHex,
                cur.types
            );
            result.push(new PacketResource(ownerName, nsec3, cls, ttl));
        }

        // RFC 5155 §4.1.2: NSEC3PARAM flags MUST be 0; the opt-out flag
        // is meaningful only inside NSEC3 records.
        const nsec3param = new NSEC3PARAM(1, 0, iterations, salt);
        result.push(new PacketResource(apex, nsec3param, cls, ttl));

        return result;
    }

    /**
     * Default TTL for synthesized DNSKEY records: the zone's SOA
     * minimum if there is one, otherwise 3600.
     * @protected
     */
    protected static _defaultDnskeyTtl(zone: Zone): number {
        try {
            return zone.soaRdata().minimum;
        } catch (_err) {
            return 3600;
        }
    }

    /**
     * Build a `DNSKEY` instance from a Node public-key `KeyObject`.
     * Inverse of the algorithm-specific `_rsaPublicKey` /
     * `_ecdsaPublicKey` / `_ed25519PublicKey` parsers.
     *
     * Convenient when generating a fresh key pair to publish: hand the
     * `publicKey` returned by `crypto.generateKeyPairSync` to this
     * method, hand the `privateKey` to `signRrset`, and the same DNSKEY
     * goes into both the published RRset and the signing path.
     */
    public static publicKeyToDnskey(
        publicKey: crypto.KeyObject,
        algorithm: number,
        flags: number = 257,
        protocol: number = 3
    ): DNSKEY {
        const keyBase64 = Dnssec._encodeDnskeyKeyField(publicKey, algorithm);
        return new DNSKEY(flags, protocol, algorithm, keyBase64);
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
     * Inverse of `_parseSigDate`: produce the YYYYMMDDHHMMSS UTC form
     * from a unix-decimal seconds value, for use as the RRSIG
     * inception/expiration string.
     * @protected
     */
    protected static _formatSigDate(timestamp: number): string {
        const date = new Date(timestamp * 1000);
        const year = date.getUTCFullYear().toString().padStart(4, '0');
        const month = (date.getUTCMonth() + 1).toString().padStart(2, '0');
        const day = date.getUTCDate().toString().padStart(2, '0');
        const hour = date.getUTCHours().toString().padStart(2, '0');
        const minute = date.getUTCMinutes().toString().padStart(2, '0');
        const second = date.getUTCSeconds().toString().padStart(2, '0');

        return `${year}${month}${day}${hour}${minute}${second}`;
    }

    /**
     * Normalize a `signRrset` inception / expiration option to the
     * RRSIG presentation form. Strings already in YYYYMMDDHHMMSS form
     * pass through unchanged; numbers and decimal-second strings are
     * formatted via `_formatSigDate`.
     * @protected
     */
    protected static _normalizeSigDate(value: string | number): string {
        if (typeof value === 'string' && /^\d{14}$/.test(value)) {
            return value;
        }

        const seconds = typeof value === 'number' ? value : parseInt(value, 10);

        if (!Number.isFinite(seconds)) {
            throw new Error(`Dnssec.signRrset: invalid date "${String(value)}"`);
        }

        return Dnssec._formatSigDate(seconds);
    }

    /**
     * Dispatch to the algorithm-specific Node `crypto.sign` invocation.
     * Mirror image of `_verifyAlgorithm` — same algorithm coverage,
     * same DNS-format conventions (raw r||s for ECDSA via
     * `dsaEncoding: 'ieee-p1363'`, raw signature for RSA, raw 64-byte
     * for Ed25519).
     * @protected
     */
    protected static _signWithAlgorithm(
        algorithm: number,
        input: Buffer,
        privateKey: crypto.KeyObject
    ): Buffer {
        switch (algorithm) {
            case DnssecAlgorithm.RSASHA256:
                return crypto.sign('sha256', input, privateKey);

            case DnssecAlgorithm.RSASHA512:
                return crypto.sign('sha512', input, privateKey);

            case DnssecAlgorithm.ECDSAP256SHA256:
                return crypto.sign('sha256', input, {key: privateKey, dsaEncoding: 'ieee-p1363'});

            case DnssecAlgorithm.ECDSAP384SHA384:
                return crypto.sign('sha384', input, {key: privateKey, dsaEncoding: 'ieee-p1363'});

            case DnssecAlgorithm.ED25519:
                return crypto.sign(null, input, privateKey);

            default:
                throw new Error(`Dnssec: unsupported signing algorithm ${algorithm}`);
        }
    }

    /**
     * Build the wire-format DNSKEY public-key field (base64) from a
     * Node `KeyObject`, dispatching on algorithm. Inverse of the
     * per-algorithm `_*PublicKey` parsers.
     * @protected
     */
    protected static _encodeDnskeyKeyField(publicKey: crypto.KeyObject, algorithm: number): string {
        switch (algorithm) {
            case DnssecAlgorithm.RSASHA256:
            case DnssecAlgorithm.RSASHA512:
                return Dnssec._encodeRsaKeyField(publicKey);

            case DnssecAlgorithm.ECDSAP256SHA256:
                return Dnssec._encodeEcdsaKeyField(publicKey, 32);

            case DnssecAlgorithm.ECDSAP384SHA384:
                return Dnssec._encodeEcdsaKeyField(publicKey, 48);

            case DnssecAlgorithm.ED25519:
                return Dnssec._encodeEd25519KeyField(publicKey);

            default:
                throw new Error(`Dnssec.publicKeyToDnskey: unsupported algorithm ${algorithm}`);
        }
    }

    /**
     * RFC 3110 RSA public-key wire format: `[explen | exponent | modulus]`.
     * `explen` is a single byte for exponents up to 255 octets, otherwise
     * 0x00 followed by a uint16 length.
     * @protected
     */
    protected static _encodeRsaKeyField(publicKey: crypto.KeyObject): string {
        const jwk = publicKey.export({format: 'jwk'}) as {n?: string; e?: string;};

        if (!jwk.n || !jwk.e) {
            throw new Error('Dnssec.publicKeyToDnskey: not an RSA public key');
        }

        const exponent = Buffer.from(jwk.e, 'base64url');
        const modulus = Buffer.from(jwk.n, 'base64url');

        let prefix: Buffer;

        if (exponent.length <= 255) {
            prefix = Buffer.from([exponent.length]);
        } else {
            prefix = Buffer.alloc(3);
            prefix.writeUInt8(0, 0);
            prefix.writeUInt16BE(exponent.length, 1);
        }

        return Buffer.concat([prefix, exponent, modulus]).toString('base64');
    }

    /**
     * ECDSA DNSKEY key field: raw uncompressed point `X || Y`, no
     * leading 0x04. JWK left-pads x/y to the curve coordinate size, but
     * we re-pad defensively in case Node ever returns minimum-length
     * representations.
     * @protected
     */
    protected static _encodeEcdsaKeyField(publicKey: crypto.KeyObject, curveBytes: number): string {
        const jwk = publicKey.export({format: 'jwk'}) as {x?: string; y?: string;};

        if (!jwk.x || !jwk.y) {
            throw new Error('Dnssec.publicKeyToDnskey: not an EC public key');
        }

        const x = Buffer.from(jwk.x, 'base64url');
        const y = Buffer.from(jwk.y, 'base64url');

        if (x.length > curveBytes || y.length > curveBytes) {
            throw new Error(
                `Dnssec.publicKeyToDnskey: EC point coordinate exceeds curve size ${curveBytes}`
            );
        }

        const padX = Buffer.concat([Buffer.alloc(curveBytes - x.length), x]);
        const padY = Buffer.concat([Buffer.alloc(curveBytes - y.length), y]);

        return Buffer.concat([padX, padY]).toString('base64');
    }

    /**
     * Ed25519 DNSKEY key field: 32-byte raw public key.
     * @protected
     */
    protected static _encodeEd25519KeyField(publicKey: crypto.KeyObject): string {
        const jwk = publicKey.export({format: 'jwk'}) as {x?: string;};

        if (!jwk.x) {
            throw new Error('Dnssec.publicKeyToDnskey: not an Ed25519 public key');
        }

        const raw = Buffer.from(jwk.x, 'base64url');

        if (raw.length !== 32) {
            throw new Error(
                `Dnssec.publicKeyToDnskey: Ed25519 key must be 32 bytes, got ${raw.length}`
            );
        }

        return raw.toString('base64');
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