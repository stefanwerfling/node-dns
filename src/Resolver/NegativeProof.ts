import {Buffer} from 'buffer';
import {Dnssec} from '../Lib/Dnssec.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {NSEC} from '../Packet/Types/NSEC.js';
import {NSEC3} from '../Packet/Types/NSEC3.js';

/* eslint-disable @typescript-eslint/no-unused-vars */

/**
 * Composer + verifier for RFC 4035 / 5155 negative-answer proofs.
 *
 * A signed authoritative server proves "this name (or this type at the
 * name) doesn't exist" by attaching NSEC or NSEC3 records to the
 * authority section instead of synthesizing the absent answer. The
 * recursor must verify those records actually prove the negative; this
 * class is the verifier.
 *
 * The four shapes are:
 *
 *  - **NXDOMAIN with NSEC** (RFC 4035 §3.1.3.2 / §5.4):
 *    1. NSEC covering `qname` (owner < qname < nextDomain in canonical order)
 *    2. NSEC covering `*.<closest_encloser>` so no wildcard could match
 *
 *  - **NODATA with NSEC** (RFC 4035 §5.4 second case):
 *    NSEC at owner == `qname` whose type bit map omits `qtype`
 *
 *  - **NXDOMAIN with NSEC3** (RFC 5155 §8.4 closest-encloser proof):
 *    1. NSEC3 matching `closest_encloser`'s hash
 *    2. NSEC3 covering `next_closer`'s hash (the next-deeper label)
 *    3. NSEC3 covering `*.<closest_encloser>`'s hash
 *
 *  - **NODATA with NSEC3** (RFC 5155 §8.5 / §8.6):
 *    NSEC3 matching `qname`'s hash, type bit map omits `qtype`
 *
 *  - **Insecure delegation with NSEC** (RFC 4035 §5.2): NSEC at the
 *    delegation owner whose bitmap lists `NS` but neither `DS` nor
 *    `SOA` (the absence of SOA disambiguates an apex from a true
 *    delegation point).
 *
 *  - **Insecure delegation with NSEC3** (RFC 5155 §8.9 / §6 opt-out):
 *    1. *Match path* — NSEC3 whose hash matches the delegation owner,
 *       bitmap has `NS` but neither `DS` nor `SOA`. This is what an
 *       NSEC3 chain *without* opt-out emits.
 *    2. *Opt-out cover path* — any NSEC3 with the opt-out flag set
 *       (RFC 5155 §3.1.2.1, bit 0) whose `(ownerHash, nextHash)`
 *       interval covers the delegation hash. With opt-out, large
 *       parent zones (`.com`, `.net`) skip explicit signing of every
 *       insecure child; the cover proves "no signed delegation
 *       exists in this hash range".
 *
 * The cryptographic verification of the NSEC / NSEC3 RRsets themselves
 * (RRSIG check) is the chain validator's job — `NegativeProof` only
 * checks that, *given* a set of NSEC/NSEC3 records the caller has
 * already authenticated, the records actually compose into a sound
 * proof of non-existence.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc4035#section-5.4
 * @docs https://datatracker.ietf.org/doc/html/rfc5155#section-8
 */
export class NegativeProof {

    /**
     * Verify an NXDOMAIN proof made of NSEC records.
     *
     * Returns `true` iff the supplied records cover both the query name
     * and the wildcard slot at the closest encloser. The closest
     * encloser is computed from the NSEC owner names plus the zone
     * apex — the recursor must pass the zone, so the apex is always
     * trusted as an existing name.
     *
     * @param {string} qname
     * @param {string} zone the signing zone of the authority section
     * @param {PacketResource[]} records authoritative NSEC records
     * @return {boolean}
     */
    public static verifyNxdomainNsec(
        qname: string,
        zone: string,
        records: PacketResource[]
    ): boolean {
        const nsecs = NegativeProof._nsecsOnly(records);

        if (nsecs.length === 0) {
            return false;
        }

        // Defensive: an NSEC at owner == qname would mean qname exists,
        // contradicting an NXDOMAIN claim.
        for (const r of nsecs) {
            if (NegativeProof._nameEquals(r.name, qname)) {
                return false;
            }
        }

        // 1. Some NSEC must cover qname.
        const coversQ = nsecs.some((r) =>
            Dnssec.nsecCovers(r.name, (r.packetType as NSEC).nextDomain, qname)
        );

        if (!coversQ) {
            return false;
        }

        // 2. Find closest encloser from NSEC owners + zone apex.
        const ce = NegativeProof.closestEncloserNsec(qname, zone, nsecs);

        if (ce === null) {
            return false;
        }

        // 3. Some NSEC must cover *.<closest_encloser> to rule out wildcard
        //    expansion. The wildcard label is the literal `*` prepended
        //    to the closest encloser.
        const wildcard = ce === '' || ce === '.' ? '*.' : `*.${ce}`;
        const coversW = nsecs.some((r) =>
            Dnssec.nsecCovers(r.name, (r.packetType as NSEC).nextDomain, wildcard)
        );

        return coversW;
    }

    /**
     * Verify a NODATA proof made of NSEC records: an NSEC at owner ==
     * `qname` whose type bit map does NOT include `qtype`.
     *
     * @param {string} qname
     * @param {number} qtype
     * @param {PacketResource[]} records
     * @return {boolean}
     */
    public static verifyNodataNsec(
        qname: string,
        qtype: number,
        records: PacketResource[]
    ): boolean {
        const nsecs = NegativeProof._nsecsOnly(records);

        for (const r of nsecs) {
            if (!NegativeProof._nameEquals(r.name, qname)) {
                continue;
            }

            const types = (r.packetType as NSEC).rdtypes;

            if (!types.includes(qtype)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Compute the closest encloser of `qname` given a set of NSEC
     * records. The closest encloser is the longest ancestor of `qname`
     * that is known to exist — concretely, the longest one that either
     *
     *   - appears as some NSEC owner, OR
     *   - equals the zone apex (always exists).
     *
     * Returns the encloser name (lowercased, no trailing dot — `''`
     * for the root) or `null` when no ancestor is known to exist
     * (which itself implies a malformed proof).
     *
     * @param {string} qname
     * @param {string} zone
     * @param {PacketResource[]} nsecs
     * @return {string|null}
     */
    public static closestEncloserNsec(
        qname: string,
        zone: string,
        nsecs: PacketResource[]
    ): string | null {
        const owners = new Set<string>();

        for (const r of nsecs) {
            if (r.packetType instanceof NSEC) {
                owners.add(NegativeProof._normalize(r.name));
            }
        }

        owners.add(NegativeProof._normalize(zone));

        // Walk qname's strict ancestors leaf → root looking for the
        // longest one we know exists.
        let candidate = NegativeProof._stripFirstLabel(NegativeProof._normalize(qname));

        while (true) {
            if (owners.has(candidate)) {
                return candidate;
            }

            if (candidate === '') {
                break;
            }

            candidate = NegativeProof._stripFirstLabel(candidate);
        }

        return null;
    }

    /**
     * Verify an NXDOMAIN proof made of NSEC3 records via the RFC 5155
     * §8.4 "closest encloser proof": find a closest encloser that
     * matches an NSEC3, find a "next closer" whose hash is covered by
     * an NSEC3, and find a `*.<closest_encloser>` whose hash is covered
     * by an NSEC3.
     *
     * @param {string} qname
     * @param {string} zone
     * @param {PacketResource[]} records authoritative NSEC3 records
     * @return {boolean}
     */
    public static verifyNxdomainNsec3(
        qname: string,
        zone: string,
        records: PacketResource[]
    ): boolean {
        const nsec3s = NegativeProof._nsec3sOnly(records);

        if (nsec3s.length === 0) {
            return false;
        }

        const params = NegativeProof._nsec3Params(nsec3s);

        if (params === null) {
            return false;
        }

        // Walk ancestors qname → zone apex looking for the closest
        // encloser. The first ancestor whose hash matches an NSEC3
        // and whose `next closer` is covered by an NSEC3 is THE
        // closest encloser, and we then check the wildcard cover.
        const labels = NegativeProof._labels(NegativeProof._normalize(qname));
        const zoneNorm = NegativeProof._normalize(zone);

        // depth=1 strips the leftmost label (closest encloser candidate
        // is the immediate parent); depth=labels.length yields '' (root).
        for (let depth = 1; depth <= labels.length; depth++) {
            const candidate = labels.slice(depth).join('.');

            if (candidate.length > 0 && !NegativeProof._isAncestorOf(candidate, zoneNorm) && candidate !== zoneNorm) {
                continue;
            }

            const ceHash = Dnssec.nsec3Hash(candidate.length === 0 ? '.' : candidate,
                params.saltHex, params.iterations);

            const ceMatch = NegativeProof._anyNsec3Matches(nsec3s, ceHash);

            if (!ceMatch) {
                continue;
            }

            const nextCloser = labels.slice(depth - 1).join('.');
            const ncHash = Dnssec.nsec3Hash(nextCloser, params.saltHex, params.iterations);

            const ncCover = NegativeProof._anyNsec3Covers(nsec3s, ncHash);

            if (!ncCover) {
                continue;
            }

            const wildcardName = candidate.length === 0 ? '*' : `*.${candidate}`;
            const wcHash = Dnssec.nsec3Hash(wildcardName, params.saltHex, params.iterations);
            const wcCover = NegativeProof._anyNsec3Covers(nsec3s, wcHash);

            if (wcCover) {
                return true;
            }
        }

        return false;
    }

    /**
     * Verify a NODATA proof made of NSEC3 records: an NSEC3 whose
     * owner-hash matches `qname`'s hash, with `qtype` absent from its
     * type bit map.
     *
     * @param {string} qname
     * @param {number} qtype
     * @param {string} zone
     * @param {PacketResource[]} records
     * @return {boolean}
     */
    public static verifyNodataNsec3(
        qname: string,
        qtype: number,
        zone: string,
        records: PacketResource[]
    ): boolean {
        const nsec3s = NegativeProof._nsec3sOnly(records);

        if (nsec3s.length === 0) {
            return false;
        }

        const params = NegativeProof._nsec3Params(nsec3s);

        if (params === null) {
            return false;
        }

        const target = Dnssec.nsec3Hash(qname, params.saltHex, params.iterations);

        for (const r of nsec3s) {
            const ownerHash = NegativeProof._extractNsec3OwnerHash(r.name);

            if (ownerHash === null || !ownerHash.equals(target)) {
                continue;
            }

            const types = (r.packetType as NSEC3).rdtypes;

            if (!types.includes(qtype)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Verify an insecure-delegation proof made of NSEC records (RFC
     * 4035 §5.2): there must be an NSEC at the delegation owner whose
     * type bitmap includes `NS` but excludes both `DS` and `SOA`.
     *
     * Excluding `SOA` is what distinguishes a delegation point from a
     * zone apex: an NS-bearing NSEC at the apex would also be missing
     * its DS, but that's a zone you ARE authoritative for, not an
     * insecure child.
     *
     * @param {string} delegationName the zone whose DS the parent denied
     * @param {PacketResource[]} records authoritative NSEC records
     * @return {boolean}
     */
    public static verifyInsecureDelegationNsec(
        delegationName: string,
        records: PacketResource[]
    ): boolean {
        const nsecs = NegativeProof._nsecsOnly(records);

        for (const r of nsecs) {
            if (!NegativeProof._nameEquals(r.name, delegationName)) {
                continue;
            }

            const types = (r.packetType as NSEC).rdtypes;

            if (NegativeProof._isInsecureBitmap(types)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Verify an insecure-delegation proof made of NSEC3 records (RFC
     * 5155 §8.9 + §6 opt-out). Two acceptable shapes:
     *
     *  1. *Match*: an NSEC3 whose owner hash equals
     *     `hash(delegationName)`, bitmap has `NS` but neither `DS`
     *     nor `SOA`. Emitted by NSEC3 chains *without* opt-out.
     *  2. *Opt-out cover*: any NSEC3 with the opt-out flag set whose
     *     `(ownerHash, nextHash)` interval covers
     *     `hash(delegationName)`. Big parent zones use opt-out to
     *     avoid signing every insecure child; this path proves "no
     *     signed delegation exists in the hash range that contains
     *     `delegationName`".
     *
     * @param {string} delegationName
     * @param {PacketResource[]} records authoritative NSEC3 records
     * @return {boolean}
     */
    public static verifyInsecureDelegationNsec3(
        delegationName: string,
        records: PacketResource[]
    ): boolean {
        const nsec3s = NegativeProof._nsec3sOnly(records);

        if (nsec3s.length === 0) {
            return false;
        }

        const params = NegativeProof._nsec3Params(nsec3s);

        if (params === null) {
            return false;
        }

        const target = Dnssec.nsec3Hash(delegationName, params.saltHex, params.iterations);

        // Path 1 — explicit match with NS-but-no-DS bitmap.
        for (const r of nsec3s) {
            const ownerHash = NegativeProof._extractNsec3OwnerHash(r.name);

            if (ownerHash === null || !ownerHash.equals(target)) {
                continue;
            }

            const types = (r.packetType as NSEC3).rdtypes;

            if (NegativeProof._isInsecureBitmap(types)) {
                return true;
            }
        }

        // Path 2 — opt-out cover. RFC 5155 §3.1.2.1: the opt-out flag
        // is bit 0 (LSB) of the flags field.
        for (const r of nsec3s) {
            const nsec3 = r.packetType as NSEC3;

            // eslint-disable-next-line no-bitwise
            if ((nsec3.flags & 0x01) === 0) {
                continue;
            }

            const ownerHash = NegativeProof._extractNsec3OwnerHash(r.name);

            if (ownerHash === null) {
                continue;
            }

            const nextHash = NegativeProof._decodeNsec3NextHash(nsec3.nextHashedOwner);

            if (nextHash === null) {
                continue;
            }

            if (Dnssec.nsec3CoversHash(ownerHash, nextHash, target)) {
                return true;
            }
        }

        return false;
    }

    /* ----------------------------------------------------------------- */
    /*  Helpers                                                          */
    /* ----------------------------------------------------------------- */

    /**
     * The bitmap shape that proves an unsigned delegation: `NS` is
     * present (the name IS a delegation) and `DS` is absent (no
     * signed link) and `SOA` is absent (the name is not a zone
     * apex).
     * @param {number[]} types
     * @return {boolean}
     * @protected
     */
    protected static _isInsecureBitmap(types: number[]): boolean {
        return types.includes(PacketTypes.NS)
            && !types.includes(PacketTypes.DS)
            && !types.includes(PacketTypes.SOA);
    }

    /**
     * @param {PacketResource[]} records
     * @return {PacketResource[]}
     * @protected
     */
    protected static _nsecsOnly(records: PacketResource[]): PacketResource[] {
        return records.filter((r) => r.packetType instanceof NSEC);
    }

    /**
     * @param {PacketResource[]} records
     * @return {PacketResource[]}
     * @protected
     */
    protected static _nsec3sOnly(records: PacketResource[]): PacketResource[] {
        return records.filter((r) => r.packetType instanceof NSEC3);
    }

    /**
     * Pull (saltHex, iterations) from the first NSEC3. Real responses
     * use one parameter set per zone, so any record is representative.
     * @param {PacketResource[]} nsec3s
     * @return {{saltHex: string; iterations: number;}|null}
     * @protected
     */
    protected static _nsec3Params(nsec3s: PacketResource[]): {saltHex: string; iterations: number;} | null {
        if (nsec3s.length === 0) {
            return null;
        }

        const first = nsec3s[0].packetType as NSEC3;
        return {saltHex: first.salt, iterations: first.iterations};
    }

    /**
     * Any NSEC3 whose owner-hash equals `target`?
     * @param {PacketResource[]} nsec3s
     * @param {Buffer} target
     * @return {boolean}
     * @protected
     */
    protected static _anyNsec3Matches(nsec3s: PacketResource[], target: Buffer): boolean {
        for (const r of nsec3s) {
            const ownerHash = NegativeProof._extractNsec3OwnerHash(r.name);

            if (ownerHash !== null && ownerHash.equals(target)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Any NSEC3 whose owner-hash..nextHashedOwner range covers
     * `target`? `nextHashedOwner` is base32hex-encoded in the rdata.
     * @param {PacketResource[]} nsec3s
     * @param {Buffer} target
     * @return {boolean}
     * @protected
     */
    protected static _anyNsec3Covers(nsec3s: PacketResource[], target: Buffer): boolean {
        for (const r of nsec3s) {
            const ownerHash = NegativeProof._extractNsec3OwnerHash(r.name);

            if (ownerHash === null) {
                continue;
            }

            const nextHash = NegativeProof._decodeNsec3NextHash((r.packetType as NSEC3).nextHashedOwner);

            if (nextHash === null) {
                continue;
            }

            if (Dnssec.nsec3CoversHash(ownerHash, nextHash, target)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The NSEC3 rdata stores nextHashedOwner as base32hex. Decode to
     * raw bytes for hash comparisons.
     * @param {string} encoded
     * @return {Buffer|null}
     * @protected
     */
    protected static _decodeNsec3NextHash(encoded: string): Buffer | null {
        try {
            return NegativeProof._base32hexDecode(encoded.toUpperCase());
        } catch {
            return null;
        }
    }

    /**
     * Decode an NSEC3 owner name's leftmost label into the raw 20-byte
     * SHA-1 hash. Returns `null` for malformed labels.
     *
     * @param {string} ownerName
     * @return {Buffer|null}
     * @protected
     */
    protected static _extractNsec3OwnerHash(ownerName: string): Buffer | null {
        const dot = ownerName.indexOf('.');
        const label = dot === -1 ? ownerName : ownerName.slice(0, dot);

        try {
            return NegativeProof._base32hexDecode(label.toUpperCase());
        } catch {
            return null;
        }
    }

    /**
     * RFC 4648 §7 base32hex decoder. Returns the raw bytes; throws on
     * invalid input.
     * @param {string} s
     * @return {Buffer}
     * @protected
     */
    protected static _base32hexDecode(s: string): Buffer {
        const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
        const padding = s.replace(/=+$/u, '');
        const bytes: number[] = [];
        let buffer = 0;
        let bits = 0;

        for (const ch of padding) {
            const v = alphabet.indexOf(ch);

            if (v === -1) {
                throw new Error(`base32hex: invalid character ${ch}`);
            }

            // eslint-disable-next-line no-bitwise
            buffer = (buffer << 5) | v;
            bits += 5;

            if (bits >= 8) {
                bits -= 8;
                // eslint-disable-next-line no-bitwise
                bytes.push((buffer >> bits) & 0xFF);
            }
        }

        return Buffer.from(bytes);
    }

    /**
     * Strip the leftmost label of `name`. Returns `''` when `name`
     * has zero or one label.
     * @param {string} name
     * @return {string}
     * @protected
     */
    protected static _stripFirstLabel(name: string): string {
        const dot = name.indexOf('.');
        return dot === -1 ? '' : name.slice(dot + 1);
    }

    /**
     * @param {string} name
     * @return {string[]}
     * @protected
     */
    protected static _labels(name: string): string[] {
        if (name === '') {
            return [];
        }

        return name.split('.');
    }

    /**
     * Is `child` equal to `parent` or a strict subdomain of it?
     * @param {string} child
     * @param {string} parent
     * @return {boolean}
     * @protected
     */
    protected static _isAncestorOf(child: string, parent: string): boolean {
        if (parent === '') {
            return true;
        }

        return child === parent || child.endsWith(`.${parent}`);
    }

    /**
     * @param {string} a
     * @param {string} b
     * @return {boolean}
     * @protected
     */
    protected static _nameEquals(a: string, b: string): boolean {
        return NegativeProof._normalize(a) === NegativeProof._normalize(b);
    }

    /**
     * @param {string} name
     * @return {string}
     * @protected
     */
    protected static _normalize(name: string): string {
        if (name === '.' || name === '') {
            return '';
        }

        const stripped = name.endsWith('.') ? name.slice(0, -1) : name;
        return stripped.toLowerCase();
    }

}