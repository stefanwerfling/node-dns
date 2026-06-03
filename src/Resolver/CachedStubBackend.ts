import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {DnsCache, DnsCacheOptions} from './DnsCache.js';
import {RCODE} from './RecursiveResolver.js';
import {extractSoa, minTtl, negativeTtl} from './utils.js';
import type {StubResolverBackend} from './StubResolver.js';

export type CachedStubBackendOptions = {
    /**
     * The cache instance to use. When omitted, a fresh `DnsCache` is
     * created from `cacheOptions` (or with `DnsCache` defaults if
     * neither is given). Pass an external instance to share it across
     * multiple stub backends or to inspect its state from outside.
     */
    cache?: DnsCache;

    /**
     * Options forwarded to the internally-created `DnsCache` when no
     * `cache` instance is provided. Ignored when `cache` is set.
     */
    cacheOptions?: DnsCacheOptions;

    /**
     * Predicate deciding whether a given upstream response is
     * cacheable. Default: cache `NOERROR` answers, `NXDOMAIN` and
     * `NODATA` per RFC 2308, and skip transient failures (`SERVFAIL`,
     * `REFUSED`, `FORMERR`, `NOTIMP`) so they aren't pinned. Override
     * if your upstream has bespoke semantics — e.g. caching `REFUSED`
     * because an ACL won't change before the next query.
     */
    isCacheable?: (response: Packet) => boolean;

    /**
     * Clock for computing TTL decrement on serve. Default
     * `() => Date.now()`. Inject in tests so the synthesized
     * response carries a deterministic TTL.
     */
    now?: () => number;
};

/**
 * Default cacheability predicate — RFC 2308 positive / negative caching
 * only. Transient upstream failures aren't cached: a `SERVFAIL` next
 * second might succeed, and pinning the failure would mask recovery.
 *
 * @param {Packet} response
 * @return {boolean}
 */
const defaultIsCacheable = (response: Packet): boolean => {
    const rcode = response.header.rcode;
    return rcode === RCODE.NOERROR || rcode === RCODE.NXDOMAIN;
};

/**
 * `StubResolverBackend` wrapper that adds a TTL-aware response cache.
 *
 * The cache sits between the `StubResolver`'s search-path expansion and
 * the actual upstream — the recommended `SystemResolver` wiring is:
 *
 *   StubResolver
 *      ↓ search-path candidate
 *   HostsFile.asResolverBackend(...)  ← authoritative for local names
 *      ↓ miss
 *   CachedStubBackend(FailoverBackend)  ← THIS layer
 *      ↓ cache miss
 *   FailoverBackend → UDPClient / DoT / ...
 *
 * Putting the cache *under* the hosts layer (rather than wrapping the
 * whole thing) preserves the usual nsswitch ordering: hosts always
 * wins for names it knows, and only real network answers consume
 * cache slots.
 *
 * What gets cached:
 *
 *   - **Positive** (`NOERROR` with answer records): the answer set
 *     stored under `(qname, qtype, qclass)` with TTL = `min(record.ttl)`
 *     per RFC 1035 §3.7. Subsequent lookups synthesize a fresh
 *     response Packet with the records cloned and their TTL
 *     decremented by the elapsed time, matching what a real recursor
 *     would emit.
 *   - **NXDOMAIN**: stored as a negative entry with TTL =
 *     `min(SOA.MINIMUM, SOA.TTL)` per RFC 2308 §5. On hit a fresh
 *     `NXDOMAIN` response is synthesized.
 *   - **NODATA** (NOERROR with empty answers): same negative-caching
 *     shape as NXDOMAIN per RFC 2308, just with `rcode = NOERROR`.
 *   - **Transient failures** (`SERVFAIL`, `REFUSED`, `FORMERR`,
 *     `NOTIMP`): *not* cached by default — the next attempt could
 *     succeed and pinning a transient failure would mask recovery.
 *     Override via `isCacheable` if your upstream's failure semantics
 *     are sticky (e.g. ACL-based REFUSED).
 *
 * Authority / additional sections from the upstream are intentionally
 * *not* preserved across a cache hit — the synthesized response has
 * just the answer records (or empty for negatives). Callers that need
 * the original SOA for negative-cache TTL inspection should look at
 * the underlying `DnsCache` directly via `.cache`.
 *
 * RFC 8767 serve-stale + BIND-style prefetch are inherited from the
 * underlying `DnsCache` — pass `cacheOptions.maxStaleSeconds` and/or
 * `cacheOptions.prefetchThreshold`. Stale hits trigger an
 * asynchronous background refresh (deduped per `(qname, qtype, qclass)`)
 * while the stale answer is returned to the caller immediately.
 *
 * The class is itself a thin callable: `new CachedStubBackend(upstream)
 * .resolve` satisfies `StubResolverBackend`, so it slots into
 * `StubResolver({resolver: ...})` or `HostsFile.asResolverBackend(...)`
 * without any adapter.
 */
export class CachedStubBackend {

    protected _upstream: StubResolverBackend;
    protected _cache: DnsCache;
    protected _isCacheable: (response: Packet) => boolean;
    protected _refreshInFlight: Set<string>;
    protected _now: () => number;

    /**
     * @param {StubResolverBackend} upstream
     * @param {CachedStubBackendOptions} options
     */
    public constructor(upstream: StubResolverBackend, options: CachedStubBackendOptions = {}) {
        if (typeof upstream !== 'function') {
            throw new Error('CachedStubBackend: upstream backend is required');
        }

        this._upstream = upstream;
        this._cache = options.cache ?? new DnsCache(options.cacheOptions);
        this._isCacheable = options.isCacheable ?? defaultIsCacheable;
        this._refreshInFlight = new Set<string>();
        this._now = options.now ?? ((): number => Date.now());
    }

    /**
     * `StubResolverBackend` view of this cache. Pass directly to
     * `new StubResolver({resolver: cached.resolve})` or
     * `HostsFile.asResolverBackend(cached.resolve)`.
     */
    public resolve: StubResolverBackend = async(
        name: string,
        type: PacketTypes | number,
        cls: PacketClass | number = PacketClass.IN
    ): Promise<Packet> => {
        const hit = this._cache.get(name, type, cls);

        if (hit !== null) {
            // Fresh hit — synthesize a response directly. `stale` and
            // `prefetch` flags signal that we should *also* kick off a
            // background refresh to update the cache for the next caller.
            if (hit.stale === true || hit.prefetch === true) {
                this._scheduleRefresh(name, type, cls);
            }

            return this._buildResponse(name, type, cls, hit);
        }

        // Cache miss — call upstream and populate the cache. We
        // deliberately don't catch errors here: a thrown upstream
        // error propagates so the StubResolver above can advance to
        // the next search-list candidate or surface the failure.
        const response = await this._upstream(name, type, cls);
        this._maybeStore(name, type, cls, response);
        return response;
    };

    /**
     * The underlying `DnsCache`. Exposed so callers can call
     * `clear()`, `size()`, `delete(name, type, cls)`, or wire the
     * same cache into multiple stub backends (e.g. one per
     * search-path domain).
     */
    public get cache(): DnsCache {
        return this._cache;
    }

    /**
     * Build a fresh response Packet from a cache entry. Records are
     * cloned with their TTLs decremented by the elapsed cache age —
     * downstream consumers (clients, other caches) see a monotonically
     * shrinking TTL, just like a real recursor would emit.
     *
     * @param {string} qname
     * @param {number} qtype
     * @param {number} qclass
     * @param {{records: PacketResource[]; rcode: string; cachedAt: number; expiresAt: number}} entry
     * @return {Packet}
     * @protected
     */
    protected _buildResponse(
        qname: string,
        qtype: PacketTypes | number,
        qclass: PacketClass | number,
        entry: {records: PacketResource[]; rcode: string; cachedAt: number; expiresAt: number}
    ): Packet {
        const out = new Packet();
        out.header.qr = 1;
        out.header.ra = 1;
        out.header.aa = 0;
        out.questions.push(new PacketQuestion(qname, qtype, qclass));

        if (entry.rcode === 'NXDOMAIN') {
            out.header.rcode = RCODE.NXDOMAIN;
            return out;
        }

        if (entry.rcode === 'NODATA') {
            out.header.rcode = RCODE.NOERROR;
            return out;
        }

        out.header.rcode = RCODE.NOERROR;
        const now = this._now();
        out.answers = entry.records.map((r) => CachedStubBackend._cloneWithAdjustedTtl(r, entry.cachedAt, now));
        return out;
    }

    /**
     * Clone a `PacketResource` with its TTL reduced by the elapsed
     * time since `cachedAt`. The original record stays untouched —
     * needed because the same cache entry may be served many times.
     *
     * @param {PacketResource} r
     * @param {number} cachedAt
     * @param {number} now
     * @return {PacketResource}
     * @protected
     */
    protected static _cloneWithAdjustedTtl(r: PacketResource, cachedAt: number, now: number): PacketResource {
        const elapsedSec = Math.floor((now - cachedAt) / 1000);
        const newTtl = Math.max(0, r.ttl - elapsedSec);
        return new PacketResource(r.name, r.packetType, r.class, newTtl);
    }

    /**
     * Decide whether to cache an upstream response, and do so.
     *
     * @param {string} qname
     * @param {number} qtype
     * @param {number} qclass
     * @param {Packet} response
     * @protected
     */
    protected _maybeStore(
        qname: string,
        qtype: PacketTypes | number,
        qclass: PacketClass | number,
        response: Packet
    ): void {
        if (!this._isCacheable(response)) {
            return;
        }

        const rcode = response.header.rcode;

        if (rcode === RCODE.NXDOMAIN) {
            // RFC 2308: derive negative TTL from min(SOA.MINIMUM, SOA.TTL).
            // No SOA → ttl = 0 → effectively not cached. That's correct
            // per the RFC and avoids pinning a malformed negative.
            const ttl = negativeTtl(extractSoa(response));

            if (ttl > 0) {
                this._cache.setNegative(qname, qtype, qclass, 'NXDOMAIN', ttl);
            }

            return;
        }

        if (rcode === RCODE.NOERROR) {
            if (response.answers.length === 0) {
                const ttl = negativeTtl(extractSoa(response));

                if (ttl > 0) {
                    this._cache.setNegative(qname, qtype, qclass, 'NODATA', ttl);
                }

                return;
            }

            // Positive answer. Take min TTL across the whole answer
            // section — preserves CNAME-chain semantics where the
            // chain's lifetime is bounded by its shortest hop.
            const ttl = minTtl(response.answers);

            if (ttl > 0) {
                this._cache.set(qname, qtype, qclass, response.answers, ttl);
            }
        }
    }

    /**
     * Fire a background re-query for `(qname, qtype, qclass)` and
     * refresh the cache when it returns. Deduped: a second stale hit
     * for the same key while a refresh is already in flight is a no-op.
     *
     * Errors are silently swallowed — the caller already got an answer
     * (the stale entry), and a transient upstream failure shouldn't
     * surface to a caller that wasn't waiting on the network anyway.
     *
     * @param {string} qname
     * @param {number} qtype
     * @param {number} qclass
     * @protected
     */
    protected _scheduleRefresh(
        qname: string,
        qtype: PacketTypes | number,
        qclass: PacketClass | number
    ): void {
        const key = `${qname.toLowerCase()}|${qtype}|${qclass}`;

        if (this._refreshInFlight.has(key)) {
            return;
        }

        this._refreshInFlight.add(key);

        // Fire-and-forget. `void` makes the floating-promise lint happy.
        void this._upstream(qname, qtype, qclass).then(
            (response) => {
                this._maybeStore(qname, qtype, qclass, response);
            },
            () => {
                // Swallow — the stale answer is already in the caller's
                // hands, and we don't want to make this a process-wide
                // unhandled rejection.
            }
        ).finally(() => {
            this._refreshInFlight.delete(key);
        });
    }

}