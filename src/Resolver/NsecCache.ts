import {Buffer} from 'buffer';
import {Dnssec} from '../Lib/Dnssec.js';
import {Packet} from '../Packet/Packet.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {NSEC} from '../Packet/Types/NSEC.js';
import {NSEC3} from '../Packet/Types/NSEC3.js';

/**
 * Per-zone cached NSEC RRset entry.
 */
export type CachedNsec = {
    owner: string;
    nextDomain: string;
    types: Set<number>;
    ttl: number;
    expiresAt: number;
};

/**
 * Per-zone cached NSEC3 RRset entry. `ownerHash` is the raw 20-byte
 * SHA-1 hash recovered from the base32hex-encoded first label of the
 * NSEC3's owner name; `nextHash` is the raw next-hashed-owner bytes
 * from the wire-format NSEC3 RDATA.
 */
export type CachedNsec3 = {
    ownerHash: Buffer;
    nextHash: Buffer;
    flags: number;
    types: Set<number>;
    ttl: number;
    expiresAt: number;
};

/**
 * NSEC3 zone parameters: the salt + iteration count needed to hash a
 * qname for membership lookup. Captured from any NSEC3 RR seen for
 * that zone (every NSEC3 in a zone carries the same parameters per
 * RFC 5155 §4).
 */
export type Nsec3Params = {
    salt: string;
    iterations: number;
};

/**
 * Result of a successful negative-answer synthesis. `ttl` is the
 * remaining TTL of the most-recently-expiring NSEC consulted, so the
 * caller can carry it forward into a synthesized response per RFC 8198
 * §5.2.
 */
export type SynthesizedNegative =
    | {kind: 'nodata'; ttl: number;}
    | {kind: 'nxdomain'; ttl: number;};

/**
 * Configuration for `NsecCache`.
 */
export type NsecCacheOptions = {
    /**
     * Optional injectable clock for deterministic tests. Defaults to
     * `Date.now`.
     */
    now?: () => number;

    /**
     * Maximum number of NSEC RRs to retain across all zones before
     * evicting (FIFO by insertion). Default: 5000. Set `0` for
     * unlimited (use only when callers control memory).
     */
    maxEntries?: number;
};

/**
 * Aggressive Use of DNSSEC-Validated Cache (RFC 8198).
 *
 * Stores NSEC / NSEC3 records observed alongside validated negative
 * answers, then synthesizes NXDOMAIN / NODATA replies for *other*
 * qnames that fall within the proven ranges without going back to
 * the upstream. The whole point is fewer round-trips against signed
 * zones whose negative-answer chains we already have evidence for.
 *
 * **Only fed with DNSSEC-validated NSEC/NSEC3 records.** Caller
 * guarantees the records were validated; this class trusts them.
 *
 * Synthesis paths in this implementation (conservative subset of
 * §5):
 *
 * 1. **NODATA via owner-match NSEC** (§5.1) — when an NSEC's owner
 *    is exactly `qname` and `qtype` is absent from the type bit map,
 *    synthesize NODATA. Safe by construction: the NSEC bitmap is
 *    authoritative about which types exist at this name.
 * 2. **NXDOMAIN via range-covering NSEC + wildcard-absence NSEC**
 *    (§5.4) — when one cached NSEC strictly covers `qname` and
 *    another cached NSEC covers the `*.<closest-encloser>` label,
 *    synthesize NXDOMAIN. Two NSECs needed because a wildcard match
 *    would otherwise resurrect the name.
 * 3. **NSEC3 NODATA** — same shape as (1) on hashed owners. Honors
 *    RFC 5155 §6 opt-out: an NSEC3 with the opt-out flag set is
 *    insufficient to prove DS/NS non-existence.
 *
 * Not implemented (yet):
 *
 * - NSEC3 NXDOMAIN range cover (needs three-NSEC3 chain: closest
 *   encloser + next closer + wildcard). The validator already has
 *   `NegativeProof.verifyNxdomainNsec3` for the equivalent shape on
 *   *fresh* responses, but the cache wiring would need to track the
 *   closest-encloser candidate set per query — added complexity for
 *   a follow-up.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc8198
 */
export class NsecCache {

    protected _nsecByZone: Map<string, CachedNsec[]> = new Map();
    protected _nsec3ByZone: Map<string, CachedNsec3[]> = new Map();
    protected _nsec3Params: Map<string, Nsec3Params> = new Map();
    protected _now: () => number;
    protected _maxEntries: number;
    protected _totalNsec: number = 0;
    protected _totalNsec3: number = 0;
    protected _insertionOrder: Array<{zone: string; kind: 'nsec' | 'nsec3'; idx: number;}> = [];

    public constructor(options: NsecCacheOptions = {}) {
        this._now = options.now ?? ((): number => Date.now());
        this._maxEntries = options.maxEntries ?? 5000;
    }

    /**
     * Drop everything cached for `zone`. Useful when the resolver
     * decides a zone's signing state has changed (e.g. key rollover
     * detected, validation bogus on a fresh response).
     *
     * @param {string} zone
     */
    public forgetZone(zone: string): void {
        const key = NsecCache._zoneKey(zone);
        const dropped = (this._nsecByZone.get(key)?.length ?? 0) + (this._nsec3ByZone.get(key)?.length ?? 0);

        this._nsecByZone.delete(key);
        this._nsec3ByZone.delete(key);
        this._nsec3Params.delete(key);
        this._totalNsec = Math.max(0, this._totalNsec - (this._nsecByZone.get(key)?.length ?? 0));
        this._totalNsec3 = Math.max(0, this._totalNsec3 - (this._nsec3ByZone.get(key)?.length ?? 0));
        this._insertionOrder = this._insertionOrder.filter((r) => r.zone !== key);
        void dropped;
    }

    /**
     * Wipe the cache.
     */
    public clear(): void {
        this._nsecByZone.clear();
        this._nsec3ByZone.clear();
        this._nsec3Params.clear();
        this._insertionOrder = [];
        this._totalNsec = 0;
        this._totalNsec3 = 0;
    }

    /**
     * Total cached NSEC + NSEC3 entries (both alive and expired —
     * expired entries are pruned lazily during `proveNegative`).
     *
     * @return {number}
     */
    public size(): number {
        return this._totalNsec + this._totalNsec3;
    }

    /**
     * Walk a validated response packet and store every NSEC / NSEC3
     * RR under `zone`. Records from the answer + authority sections
     * are considered; additionals are skipped (NSECs don't live
     * there in practice). Caller asserts the response was DNSSEC-
     * validated.
     *
     * @param {Packet} packet
     * @param {string} zone
     */
    public storeFromResponse(packet: Packet, zone: string): void {
        for (const r of packet.answers) {
            this._storeRecord(r.name, r.ttl, r.packetType, zone);
        }

        for (const r of packet.authorities) {
            this._storeRecord(r.name, r.ttl, r.packetType, zone);
        }
    }

    /**
     * Look up a cached proof for `(qname, qtype, qclass)`. Returns
     * `null` if nothing matches.
     *
     * @param {string} qname
     * @param {number} qtype
     * @return {SynthesizedNegative|null}
     */
    public proveNegative(qname: string, qtype: number): SynthesizedNegative | null {
        const nodataNsec = this._proveNodataViaNsec(qname, qtype);

        if (nodataNsec !== null) {
            return nodataNsec;
        }

        const nodataNsec3 = this._proveNodataViaNsec3(qname, qtype);

        if (nodataNsec3 !== null) {
            return nodataNsec3;
        }

        const nxdomainNsec = this._proveNxdomainViaNsec(qname);

        if (nxdomainNsec !== null) {
            return nxdomainNsec;
        }

        const nxdomainNsec3 = this._proveNxdomainViaNsec3(qname);

        if (nxdomainNsec3 !== null) {
            return nxdomainNsec3;
        }

        return null;
    }

    /**
     * Store the NSEC3PARAM hashing knobs for `zone`. The recursor
     * extracts these from any NSEC3 it sees in the zone and caches
     * them so subsequent `proveNegative` calls can hash candidate
     * qnames the same way. Overwrites any prior value (the zone
     * operator may rotate salt across rollovers).
     *
     * @param {string} zone
     * @param {Nsec3Params} params
     */
    public setNsec3Params(zone: string, params: Nsec3Params): void {
        this._nsec3Params.set(NsecCache._zoneKey(zone), params);
    }

    /**
     * Read back the cached NSEC3 params for `zone`, or `null` if
     * none have been observed.
     *
     * @param {string} zone
     * @return {Nsec3Params|null}
     */
    public getNsec3Params(zone: string): Nsec3Params | null {
        return this._nsec3Params.get(NsecCache._zoneKey(zone)) ?? null;
    }

    protected static _zoneKey(zone: string): string {
        return zone.toLowerCase().replace(/\.$/u, '');
    }

    protected static _nameKey(name: string): string {
        return name.toLowerCase().replace(/\.$/u, '');
    }

    protected _storeRecord(owner: string, ttl: number, packetType: unknown, zone: string): void {
        const now = this._now();

        if (packetType instanceof NSEC) {
            const entry: CachedNsec = {
                owner: NsecCache._nameKey(owner),
                nextDomain: NsecCache._nameKey(packetType.nextDomain),
                types: new Set(packetType.rdtypes),
                ttl: ttl,
                expiresAt: now + (ttl * 1000)
            };

            const key = NsecCache._zoneKey(zone);
            const bucket = this._nsecByZone.get(key) ?? [];
            const replaceIdx = bucket.findIndex((e) => e.owner === entry.owner);

            if (replaceIdx === -1) {
                bucket.push(entry);
                this._totalNsec++;
                this._insertionOrder.push({zone: key, kind: 'nsec', idx: bucket.length - 1});
            } else {
                bucket[replaceIdx] = entry;
            }

            this._nsecByZone.set(key, bucket);
            this._evictIfNeeded();
            return;
        }

        if (packetType instanceof NSEC3) {
            const ownerLabel = owner.split('.', 1)[0];
            const ownerHash = NsecCache._decodeBase32Hex(ownerLabel);

            if (ownerHash === null) {
                return;
            }

            const nextHash = Buffer.from(packetType.nextHashedOwner, 'hex');

            const entry: CachedNsec3 = {
                ownerHash: ownerHash,
                nextHash: nextHash,
                flags: packetType.flags,
                types: new Set(packetType.rdtypes),
                ttl: ttl,
                expiresAt: now + (ttl * 1000)
            };

            const key = NsecCache._zoneKey(zone);
            const bucket = this._nsec3ByZone.get(key) ?? [];
            const replaceIdx = bucket.findIndex((e) => Buffer.compare(e.ownerHash, entry.ownerHash) === 0);

            if (replaceIdx === -1) {
                bucket.push(entry);
                this._totalNsec3++;
                this._insertionOrder.push({zone: key, kind: 'nsec3', idx: bucket.length - 1});
            } else {
                bucket[replaceIdx] = entry;
            }

            this._nsec3ByZone.set(key, bucket);

            // Capture the zone's NSEC3 params from the record itself.
            this._nsec3Params.set(key, {
                salt: packetType.salt,
                iterations: packetType.iterations
            });

            this._evictIfNeeded();
        }
    }

    protected _evictIfNeeded(): void {
        if (this._maxEntries === 0) {
            return;
        }

        while (this._totalNsec + this._totalNsec3 > this._maxEntries && this._insertionOrder.length > 0) {
            const oldest = this._insertionOrder.shift()!;
            const bucket = oldest.kind === 'nsec'
                ? this._nsecByZone.get(oldest.zone)
                : this._nsec3ByZone.get(oldest.zone);

            if (bucket && bucket.length > 0) {
                bucket.shift();

                if (oldest.kind === 'nsec') {
                    this._totalNsec--;
                } else {
                    this._totalNsec3--;
                }
            }
        }
    }

    protected _proveNodataViaNsec(qname: string, qtype: number): SynthesizedNegative | null {
        const qkey = NsecCache._nameKey(qname);
        const now = this._now();

        for (const [, bucket] of this._nsecByZone) {
            for (const entry of bucket) {
                if (entry.expiresAt <= now) {
                    continue;
                }

                if (entry.owner !== qkey) {
                    continue;
                }

                if (entry.types.has(qtype)) {
                    return null;
                }

                // RFC 4035 §5.4 — CNAME shadow check: if the bitmap has
                // CNAME, every type at this owner is supposed to be a
                // CNAME redirect, so synthesizing NODATA is wrong.
                if (entry.types.has(PacketTypes.CNAME)) {
                    return null;
                }

                return {kind: 'nodata', ttl: NsecCache._remainingSeconds(entry.expiresAt, now)};
            }
        }

        return null;
    }

    protected _proveNxdomainViaNsec(qname: string): SynthesizedNegative | null {
        const qkey = NsecCache._nameKey(qname);
        const now = this._now();

        for (const [zoneKey, bucket] of this._nsecByZone) {
            const cover = bucket.find((e) =>
                e.expiresAt > now &&
                Dnssec.nsecCovers(e.owner, e.nextDomain, qkey)
            );

            if (!cover) {
                continue;
            }

            const closestEncloser = NsecCache._closestEncloser(qkey, cover.owner, cover.nextDomain, zoneKey);

            if (closestEncloser === null) {
                continue;
            }

            const wildcard = `*.${closestEncloser}`;
            const wildcardCover = bucket.find((e) =>
                e.expiresAt > now &&
                (e.owner === wildcard || Dnssec.nsecCovers(e.owner, e.nextDomain, wildcard))
            );

            if (!wildcardCover) {
                continue;
            }

            if (wildcardCover.owner === wildcard) {
                // Wildcard exists at the closest encloser — cannot
                // synthesize NXDOMAIN, the wildcard could match.
                continue;
            }

            const minRemaining = Math.min(
                NsecCache._remainingSeconds(cover.expiresAt, now),
                NsecCache._remainingSeconds(wildcardCover.expiresAt, now)
            );

            return {kind: 'nxdomain', ttl: minRemaining};
        }

        return null;
    }

    /**
     * NSEC3 NXDOMAIN synthesis (RFC 8198 §5.4 over RFC 5155 §8.4):
     * walk ancestors of `qname` looking for one whose hash matches a
     * cached NSEC3 (= closest encloser exists), then verify the
     * `next-closer` (one label deeper) is covered by a cached NSEC3
     * and the synthesised wildcard `*.<closest-encloser>` is also
     * covered.
     *
     * Opt-out (RFC 5155 §6 / RFC 7129 §5.5): a name covered by an
     * opt-out NSEC3 might still exist as an unsigned delegation, so
     * the synthesis is refused whenever the next-closer or wildcard
     * cover comes from an opt-out NSEC3.
     *
     * @param {string} qname
     * @return {SynthesizedNegative|null}
     * @protected
     */
    protected _proveNxdomainViaNsec3(qname: string): SynthesizedNegative | null {
        const qkey = NsecCache._nameKey(qname);
        const now = this._now();
        const qLabels = qkey.split('.').filter((l) => l.length > 0);

        for (const [zoneKey, bucket] of this._nsec3ByZone) {
            const params = this._nsec3Params.get(zoneKey);

            if (!params) {
                continue;
            }

            const zoneLabels = zoneKey.split('.').filter((l) => l.length > 0);

            if (qLabels.length <= zoneLabels.length) {
                continue;
            }

            // Walk ancestors qname → zone apex. depth = labels stripped
            // from the left. depth=1 → immediate parent; depth=N → root.
            for (let depth = 1; depth <= qLabels.length - zoneLabels.length; depth++) {
                const candidateLabels = qLabels.slice(depth);
                const candidate = candidateLabels.join('.');

                if (candidate.length === 0) {
                    continue;
                }

                let ceHash: Buffer;

                try {
                    ceHash = Dnssec.nsec3Hash(candidate, params.salt, params.iterations);
                } catch {
                    continue;
                }

                const ceMatch = bucket.find((e) =>
                    e.expiresAt > now &&
                    Buffer.compare(e.ownerHash, ceHash) === 0
                );

                if (!ceMatch) {
                    continue;
                }

                // Next-closer = one label deeper than the closest encloser
                // (i.e. depth - 1 stripped from the left).
                const nextCloserLabels = qLabels.slice(depth - 1);
                const nextCloser = nextCloserLabels.join('.');

                let ncHash: Buffer;

                try {
                    ncHash = Dnssec.nsec3Hash(nextCloser, params.salt, params.iterations);
                } catch {
                    continue;
                }

                const ncCover = bucket.find((e) =>
                    e.expiresAt > now &&
                    Dnssec.nsec3CoversHash(e.ownerHash, e.nextHash, ncHash)
                );

                if (!ncCover) {
                    continue;
                }

                // RFC 5155 §6 — opt-out blocks NXDOMAIN synthesis
                // because the next closer might be an unsigned
                // delegation that actually exists.
                // eslint-disable-next-line no-bitwise
                if ((ncCover.flags & 0x01) === 1) {
                    continue;
                }

                const wildcardName = `*.${candidate}`;

                let wcHash: Buffer;

                try {
                    wcHash = Dnssec.nsec3Hash(wildcardName, params.salt, params.iterations);
                } catch {
                    continue;
                }

                const wcCover = bucket.find((e) =>
                    e.expiresAt > now &&
                    Dnssec.nsec3CoversHash(e.ownerHash, e.nextHash, wcHash)
                );

                if (!wcCover) {
                    continue;
                }

                // eslint-disable-next-line no-bitwise
                if ((wcCover.flags & 0x01) === 1) {
                    continue;
                }

                const minRemaining = Math.min(
                    NsecCache._remainingSeconds(ceMatch.expiresAt, now),
                    NsecCache._remainingSeconds(ncCover.expiresAt, now),
                    NsecCache._remainingSeconds(wcCover.expiresAt, now)
                );

                return {kind: 'nxdomain', ttl: minRemaining};
            }
        }

        return null;
    }

    protected _proveNodataViaNsec3(qname: string, qtype: number): SynthesizedNegative | null {
        const qkey = NsecCache._nameKey(qname);
        const now = this._now();

        for (const [zoneKey, bucket] of this._nsec3ByZone) {
            const params = this._nsec3Params.get(zoneKey);

            if (!params) {
                continue;
            }

            let qhash: Buffer;

            try {
                qhash = Dnssec.nsec3Hash(qkey, params.salt, params.iterations);
            } catch {
                continue;
            }

            const match = bucket.find((e) =>
                e.expiresAt > now &&
                Buffer.compare(e.ownerHash, qhash) === 0
            );

            if (!match) {
                continue;
            }

            // RFC 5155 §6 — an opt-out NSEC3 can't prove anything
            // about delegation types since unsigned delegations may
            // fall in its covered range without entry. For NODATA at
            // an owner match this is moot for non-DS/NS types, but
            // be conservative: skip opt-out matches.
            // eslint-disable-next-line no-bitwise
            const optOut = (match.flags & 0x01) === 1;

            if (optOut && (qtype === PacketTypes.NS || qtype === PacketTypes.DS)) {
                continue;
            }

            if (match.types.has(qtype)) {
                return null;
            }

            if (match.types.has(PacketTypes.CNAME)) {
                return null;
            }

            return {kind: 'nodata', ttl: NsecCache._remainingSeconds(match.expiresAt, now)};
        }

        return null;
    }

    /**
     * Find the closest existing ancestor of `qname` based on a NSEC
     * range. The closest encloser is the longest suffix of `qname`
     * that is provably an ancestor of both `owner` and `next`.
     *
     * For NSEC range cover (`owner < qname < next`), the closest
     * encloser is the longest common suffix of (owner, next) that is
     * also a suffix of qname.
     *
     * Returns the closest encloser as a lowercased name without
     * trailing dot, or `null` when none can be inferred (e.g. the
     * cover is wrap-around at the zone apex, or the chain doesn't
     * give us a usable suffix).
     */
    protected static _closestEncloser(
        qname: string,
        owner: string,
        next: string,
        zone: string
    ): string | null {
        const qLabels = qname.split('.').filter((l) => l.length > 0);
        const oLabels = owner.split('.').filter((l) => l.length > 0);
        const nLabels = next.split('.').filter((l) => l.length > 0);

        const commonSuffix = (a: string[], b: string[]): string[] => {
            const out: string[] = [];

            for (let i = 0; i < Math.min(a.length, b.length); i++) {
                const la = a[a.length - 1 - i];
                const lb = b[b.length - 1 - i];

                if (la === lb) {
                    out.unshift(la);
                } else {
                    break;
                }
            }

            return out;
        };

        const ownerNext = commonSuffix(oLabels, nLabels);
        const ownerQ = commonSuffix(oLabels, qLabels);
        const nextQ = commonSuffix(nLabels, qLabels);

        let closest = ownerQ;

        if (nextQ.length > closest.length) {
            closest = nextQ;
        }

        // Closest encloser is the longest common suffix among
        // (qname, owner) and (qname, next) that is also a suffix of
        // (owner, next).
        if (closest.length > ownerNext.length) {
            closest = ownerNext;
        }

        if (closest.length === 0) {
            return null;
        }

        const candidate = closest.join('.');

        // Must be inside the zone — protects against degenerate
        // cases where the cover crosses out of zone.
        if (zone.length > 0 && !candidate.endsWith(zone)) {
            return null;
        }

        return candidate;
    }

    protected static _decodeBase32Hex(input: string): Buffer | null {
        const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
        const upper = input.toUpperCase();
        const bytes: number[] = [];
        let value = 0;
        let bits = 0;

        for (const ch of upper) {
            const v = alphabet.indexOf(ch);

            if (v === -1) {
                return null;
            }

            // eslint-disable-next-line no-bitwise
            value = (value << 5) | v;
            bits += 5;

            if (bits >= 8) {
                bits -= 8;
                // eslint-disable-next-line no-bitwise
                bytes.push((value >>> bits) & 0xFF);
            }
        }

        return Buffer.from(bytes);
    }

    protected static _remainingSeconds(expiresAt: number, now: number): number {
        return Math.max(0, Math.floor((expiresAt - now) / 1000));
    }

}