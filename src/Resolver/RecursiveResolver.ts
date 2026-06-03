import {Bailiwick} from '../Lib/Bailiwick.js';
import {DnssecVerifyOptions} from '../Lib/Dnssec.js';
import {Random0x20} from '../Lib/Random0x20.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {AAAA} from '../Packet/Types/AAAA.js';
import {CNAME} from '../Packet/Types/CNAME.js';
import {EDNS} from '../Packet/Types/EDNS.js';
import {DNAME} from '../Packet/Types/DNAME.js';
import {NS} from '../Packet/Types/NS.js';
import {DnsCache} from './DnsCache.js';
import {DnssecValidator, DnssecMode} from './DnssecValidator.js';
import {RootHints, RootServer} from './RootHints.js';
import {defaultTcpTransport, defaultUdpTransport} from './Transports.js';
import {TrustAnchor, TrustAnchors} from './TrustAnchor.js';
import {
    extractSoa,
    isStrictlyDeeper,
    labels as labelsOf,
    minTtl,
    minimizeQname,
    nameEquals,
    negativeTtl,
    withTimeout
} from './utils.js';

/**
 * Standard DNS RCODEs (RFC 1035 §4.1.1, RFC 6895). Inlined here so the
 * resolver doesn't depend on a transport-specific enum.
 */
export const RCODE: {
    readonly NOERROR: 0;
    readonly FORMERR: 1;
    readonly SERVFAIL: 2;
    readonly NXDOMAIN: 3;
    readonly NOTIMP: 4;
    readonly REFUSED: 5;
} = Object.freeze({
    NOERROR: 0 as const,
    FORMERR: 1 as const,
    SERVFAIL: 2 as const,
    NXDOMAIN: 3 as const,
    NOTIMP: 4 as const,
    REFUSED: 5 as const
});

/**
 * Transport callback the resolver uses to talk to authoritative servers.
 *
 * Default: a plain UDP datagram. Tests inject a deterministic mock so
 * the suite can exercise iterative resolution without real network
 * access.
 *
 * Implementations must:
 *  - send `query` to `serverIp:port`,
 *  - wait for a single response (no streaming),
 *  - return the parsed `Packet`,
 *  - reject on timeout or error.
 *
 * The resolver enforces a per-query timeout via a `Promise.race` wrapper
 * outside the transport, so transports do not need their own timer
 * (though they may add one).
 */
export type RecursiveResolverTransport = (
    serverIp: string,
    port: number,
    query: Packet
) => Promise<Packet>;

// Re-export of `DnssecMode` from the validator module for back-compat
// with callers that imported it from `RecursiveResolver`.
export type {DnssecMode};

/**
 * Per-resolver DNSSEC configuration.
 */
export type DnssecResolverOptions = {
    /**
     * Trust anchors. Defaults to `TrustAnchors.DEFAULT` (IANA root
     * KSK-2017). Pass a custom list for split-horizon or RFC 8806
     * local-root deployments.
     */
    trustAnchors?: ReadonlyArray<TrustAnchor>;

    /**
     * Failure policy. Default: `permissive`.
     */
    mode?: DnssecMode;

    /**
     * Forwarded to `Dnssec.verifyRrsig` — fixed clock for tests.
     */
    verifyOptions?: DnssecVerifyOptions;
};

/**
 * Configuration for `RecursiveResolver`.
 */
export type RecursiveResolverOptions = {
    /**
     * Cache instance. A new `DnsCache` is created when omitted; the
     * resolver primes it with `RootHints.DEFAULT` either way.
     */
    cache?: DnsCache;

    /**
     * Override the bundled root hints. Useful for tests, RFC 8806 local
     * roots, or split-horizon deployments.
     */
    rootHints?: ReadonlyArray<RootServer>;

    /**
     * Transport callback. Default: UDP via Node `dgram`.
     */
    transport?: RecursiveResolverTransport;

    /**
     * RFC 5452 §9.2 case randomization on outgoing queries — flips ASCII
     * letters in QNAME at random and verifies the response echoed the
     * exact case. Default: true.
     */
    use0x20?: boolean;

    /**
     * Wallclock budget for one `resolve()` call (milliseconds). Default:
     * 10000.
     */
    timeoutMs?: number;

    /**
     * Per-query timeout (milliseconds). Default: 2000.
     */
    queryTimeoutMs?: number;

    /**
     * Maximum upstream queries issued during a single resolution.
     * Bounds the worst-case work for misbehaved zones (referral loops,
     * very long delegation chains). Default: 50.
     */
    maxQueries?: number;

    /**
     * Maximum CNAME chain length followed during a single resolution.
     * Default: 16 (matches BIND).
     */
    maxCnameDepth?: number;

    /**
     * Default UDP port queried. Default: 53.
     */
    port?: number;

    /**
     * Retry over TCP (RFC 7766 §5) when an upstream replies with the
     * truncation bit set (TC=1). Default: true.
     */
    tcpFallback?: boolean;

    /**
     * Default TCP port queried for the truncation retry. Default: 53.
     */
    tcpPort?: number;

    /**
     * Transport callback used for the TC=1 retry. Default: a one-shot
     * length-prefixed connection via Node `net`. Mocks can supply an
     * alternate implementation alongside `transport` to drive
     * deterministic UDP / TCP routes in tests.
     */
    tcpTransport?: RecursiveResolverTransport;

    /**
     * Append an EDNS(0) OPT RR to outgoing queries (RFC 6891). The OPT
     * advertises `udpPayloadSize` so the upstream may send a larger UDP
     * response without fragmenting or truncating, cutting roundtrips
     * for medium-size answers (DNSSEC chains, multi-record RRsets).
     *
     * Default: true.
     */
    useEdns?: boolean;

    /**
     * UDP payload size advertised in the EDNS OPT RR (RFC 6891 §6.2.3).
     * Common settings: 1232 (DNS Flag Day 2020 — fits in PMTU-1500
     * minus IPv6 + UDP overhead with IPsec headroom), 4096 (legacy
     * BIND default), 512 (no benefit over non-EDNS).
     *
     * Default: 4096.
     */
    udpPayloadSize?: number;

    /**
     * Enable DNSSEC validation. `true` uses bundled IANA trust anchors
     * and `permissive` mode; pass an object for finer-grained control.
     * Default: disabled — answers pass through unvalidated.
     */
    dnssec?: boolean | DnssecResolverOptions;

    /**
     * QNAME minimization (RFC 9156). At each delegation step, send a
     * truncated QNAME (one label deeper than the cached zone) with
     * `qtype = NS` instead of the full qname with the real qtype.
     * Roots / TLDs / intermediates therefore see only the portion of
     * the qname they actually need to delegate on. The full qname +
     * real qtype is sent only to the authoritative server for the
     * leaf zone. Default: `true` (RFC 9156 says SHOULD).
     */
    qnameMinimization?: boolean;

    /**
     * Number of labels to add per minimization step (RFC 9156 §3.3
     * permits more than one for fewer roundtrips, at the cost of
     * leaking more of the qname to intermediates). Default: 1, the
     * strictest privacy setting.
     */
    qnameMinimizationLabelsPerStep?: number;
};

/**
 * Per-call options that override resolver defaults.
 */
export type ResolveOptions = {
    qclass?: PacketClass;
    timeoutMs?: number;
    queryTimeoutMs?: number;
    maxQueries?: number;
    maxCnameDepth?: number;
};

/**
 * Iterative recursive resolver (RFC 1034 §5, RFC 1035 §7).
 *
 * Starts at the root delegation seeded from `RootHints`, walks the
 * referral chain downward following NS records, follows CNAMEs, and
 * caches every observed RRset by its `(name, type, class)` key.
 *
 * The resolver is intentionally minimal in its first incarnation:
 *
 *  - **DNSSEC validation** is opt-in via `dnssec`. When enabled, the
 *    resolver composes a `DnssecValidator` that walks the chain from a
 *    configured trust anchor, validates every signed RRset, and sets
 *    the AD bit on authentic answers (RFC 4035 §3.2). Disabled answers
 *    pass through unvalidated.
 *  - **TCP fallback on TC=1** is on by default (RFC 7766 §5). When an
 *    upstream replies with the truncation bit set the same question is
 *    reissued over TCP via the configurable `tcpTransport`. Opt out via
 *    `tcpFallback: false`; override the port via `tcpPort`.
 *  - **EDNS(0) buffer negotiation** is on by default (RFC 6891). Each
 *    outgoing query carries an OPT RR advertising
 *    `udpPayloadSize` (default 4096) so upstreams can reply with
 *    larger UDP messages and avoid the TCP retry. Opt out via
 *    `useEdns: false`.
 *  - **No prefetch or stale-while-revalidate.** Cache entries simply
 *    expire and the next query re-resolves from scratch.
 *
 * Spoofing defenses already in place: a fresh random 16-bit ID per
 * query, RFC 5452 §6 bailiwick filtering on every response, and RFC
 * 5452 §9.2 case randomization (0x20).
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc1034#section-5
 * @docs https://datatracker.ietf.org/doc/html/rfc1035#section-7
 */
export class RecursiveResolver {

    /**
     * @protected
     */
    protected _cache: DnsCache;

    /**
     * @protected
     */
    protected _transport: RecursiveResolverTransport;

    /**
     * @protected
     */
    protected _use0x20: boolean;

    /**
     * @protected
     */
    protected _timeoutMs: number;

    /**
     * @protected
     */
    protected _queryTimeoutMs: number;

    /**
     * @protected
     */
    protected _maxQueries: number;

    /**
     * @protected
     */
    protected _maxCnameDepth: number;

    /**
     * @protected
     */
    protected _port: number;

    /**
     * @protected
     */
    protected _tcpFallback: boolean;

    /**
     * @protected
     */
    protected _tcpPort: number;

    /**
     * @protected
     */
    protected _tcpTransport: RecursiveResolverTransport;

    /**
     * @protected
     */
    protected _useEdns: boolean;

    /**
     * Per-server learned UDP buffer size. Populated whenever a response
     * carries an OPT RR whose CLASS field (the server's advertised
     * payload size, RFC 6891 §6.1.2) is smaller than our configured
     * `_udpPayloadSize`. Subsequent queries to the same server use the
     * smaller value so we don't ask for more than the server can ship
     * — RFC 6891 §6.2.3 says the requestor MAY downgrade based on the
     * responder's advertised maximum.
     * @protected
     */
    protected _serverBuffers: Map<string, number>;

    /**
     * In-flight serve-stale refresh keys — `<qname>|<qtype>|<qclass>`.
     * Used to dedupe: if a refresh is already running for a given
     * triple, a second stale hit on the same key won't kick off
     * another. RFC 8767 §6 calls out the stampede risk explicitly.
     * @protected
     */
    protected _refreshInFlight: Set<string>;

    /**
     * @protected
     */
    protected _udpPayloadSize: number;

    /**
     * @protected
     */
    protected _dnssecEnabled: boolean;

    /**
     * The DNSSEC validator instance. Constructed only when `dnssec` is
     * truthy in the options. Held as a separate object because DNSSEC
     * is a self-contained concern — the resolver delegates to it via
     * `_dnssecFinalize` after each authoritative answer.
     * @protected
     */
    protected _dnssecValidator: DnssecValidator | null;

    /**
     * RFC 9156 QNAME minimization toggle. When `true`, the resolver
     * sends truncated qnames to intermediate nameservers.
     * @protected
     */
    protected _qnameMinimization: boolean;

    /**
     * Number of labels added per minimization step.
     * @protected
     */
    protected _qnameMinimizationLabelsPerStep: number;

    /**
     * @param {RecursiveResolverOptions} options
     */
    public constructor(options: RecursiveResolverOptions = {}) {
        this._cache = options.cache ?? new DnsCache();
        this._transport = options.transport ?? defaultUdpTransport;
        this._use0x20 = options.use0x20 ?? true;
        this._timeoutMs = options.timeoutMs ?? 10_000;
        this._queryTimeoutMs = options.queryTimeoutMs ?? 2_000;
        this._maxQueries = options.maxQueries ?? 50;
        this._maxCnameDepth = options.maxCnameDepth ?? 16;
        this._port = options.port ?? 53;
        this._tcpFallback = options.tcpFallback ?? true;
        this._tcpPort = options.tcpPort ?? 53;
        this._tcpTransport = options.tcpTransport ?? defaultTcpTransport;
        this._useEdns = options.useEdns ?? true;
        this._udpPayloadSize = options.udpPayloadSize ?? 4096;
        this._serverBuffers = new Map();
        this._refreshInFlight = new Set();

        this._qnameMinimization = options.qnameMinimization ?? true;
        this._qnameMinimizationLabelsPerStep = Math.max(1, options.qnameMinimizationLabelsPerStep ?? 1);

        const dnssecOpt = options.dnssec;
        this._dnssecEnabled = dnssecOpt !== undefined && dnssecOpt !== false;

        if (this._dnssecEnabled) {
            const dnssecObj = typeof dnssecOpt === 'object' ? dnssecOpt : {};
            this._dnssecValidator = new DnssecValidator(this, {
                trustAnchors: dnssecObj.trustAnchors ?? TrustAnchors.DEFAULT,
                mode: dnssecObj.mode ?? 'permissive',
                verifyOptions: dnssecObj.verifyOptions ?? {}
            });
        } else {
            this._dnssecValidator = null;
        }

        RootHints.seedCache(this._cache, options.rootHints);
    }

    /**
     * Underlying cache. Exposed so callers can pre-seed with stub-zone
     * data, inspect / dump entries, or wire a metrics hook around it.
     * @return {DnsCache}
     */
    public cache(): DnsCache {
        return this._cache;
    }

    /**
     * Resolve `(qname, qtype)`. Returns a `Packet` shaped like a
     * recursive answer:
     *
     *  - `header.qr = 1`, `header.ra = 1`
     *  - `header.aa = 0` (we are not the authority)
     *  - `header.rcode` set to `NOERROR` / `NXDOMAIN` / `SERVFAIL`
     *  - `answers` carries the followed CNAME chain plus the final RRset
     *  - `authorities` carries the final SOA on negative answers
     *
     * Throws on transport-level catastrophes (no cached NS, total
     * timeout, all servers unreachable) — those surface as `SERVFAIL`
     * to a caller that wraps `resolve()` in `try/catch`.
     *
     * @param {string} qname
     * @param {number|PacketTypes} qtype
     * @param {ResolveOptions} options
     * @return {Promise<Packet>}
     */
    public async resolve(
        qname: string,
        qtype: number | PacketTypes,
        options: ResolveOptions = {}
    ): Promise<Packet> {
        const qclass = options.qclass ?? PacketClass.IN;
        const ctx: ResolveCtx = {
            startTime: Date.now(),
            timeoutMs: options.timeoutMs ?? this._timeoutMs,
            queryTimeoutMs: options.queryTimeoutMs ?? this._queryTimeoutMs,
            maxQueries: options.maxQueries ?? this._maxQueries,
            maxCnameDepth: options.maxCnameDepth ?? this._maxCnameDepth,
            queriesIssued: 0,
            cnameDepth: 0,
            chain: [],
            visited: new Set(),
            originalQname: qname,
            originalQtype: qtype,
            qclass: qclass
        };

        try {
            return await this._resolveOnce(qname, qtype, qclass, ctx);
        } catch (err) {
            return RecursiveResolver._buildResponse(ctx, RCODE.SERVFAIL, [], []);
        }
    }

    /**
     * Run one resolution starting at `qname/qtype`. Recursive calls land
     * here too — sub-resolutions for glueless NS share the same
     * `ctx` so iteration / time budgets accumulate.
     * @protected
     */
    /** @internal */
    public async _resolveOnce(
        qname: string,
        qtype: number | PacketTypes,
        qclass: PacketClass,
        ctx: ResolveCtx
    ): Promise<Packet> {
        // Direct cache hit on the requested (qname, qtype)?
        // Skip the cache check for refresh resolutions — those are
        // explicitly asking the upstream chain for fresh data.
        if (ctx.bypassCache !== true) {
            const direct = this._cache.get(qname, qtype, qclass);

            if (direct !== null) {
                if (direct.stale === true || direct.prefetch === true) {
                    // RFC 8767 (stale) / BIND-style prefetch — return
                    // the cached answer to this caller immediately and
                    // kick off an async refresh so the next caller
                    // sees fresh data. Prefetch fires *before* expiry
                    // so the cached entry stays valid until the
                    // refresh completes.
                    this._scheduleRefresh(qname, qtype, qclass);
                }

                return RecursiveResolver._cacheEntryToResponse(ctx, direct);
            }

            // Cached CNAME at qname → follow it (when qtype isn't CNAME itself).
            if (qtype !== PacketTypes.CNAME) {
                const cnameHit = this._cache.get(qname, PacketTypes.CNAME, qclass);

                if (cnameHit !== null && cnameHit.records.length > 0) {
                    if (cnameHit.stale === true || cnameHit.prefetch === true) {
                        this._scheduleRefresh(qname, PacketTypes.CNAME, qclass);
                    }

                    return this._followCnameFromCache(qname, qtype, qclass, ctx, cnameHit.records);
                }
            }
        }

        // Iterative resolution loop.
        const currentName = qname;
        const currentType = qtype;
        let lastResponse: Packet | null = null;

        // RFC 9156 §3 fallback flag — toggled when an intermediate server
        // mishandles the minimized probe (e.g. returns SERVFAIL on
        // (parent.zone, NS)). Local to this resolution; CNAME chase
        // sub-resolutions reset to their own decision.
        let minimizationDisabled = false;

        // outer loop: each iteration walks one delegation step closer to the answer.
        for (let safety = 0; safety < ctx.maxQueries; safety++) {
            this._guardBudget(ctx);

            const nsZone = this._findClosestNs(currentName, qclass);

            if (nsZone === null) {
                // Should never happen — root NS are seeded in ctor.
                throw new Error('RecursiveResolver: no cached NS for any ancestor');
            }

            const nsAddr = await this._pickNsAddress(nsZone, qclass, ctx);

            if (nsAddr === null) {
                throw new Error(`RecursiveResolver: no usable address for any NS of ${nsZone.zone}`);
            }

            // Decide what to actually send to this server: a minimized
            // probe (RFC 9156) or the real (qname, qtype) pair. Skip
            // minimization on auth-chain queries since DNSKEY/DS lookups
            // already target the exact name they need.
            let sendName: string = currentName;
            let sendType: number | PacketTypes = currentType;
            let isMinimized = false;

            if (this._qnameMinimization && !minimizationDisabled && ctx.inAuthChain !== true) {
                const probe = minimizeQname(qname, nsZone.zone, this._qnameMinimizationLabelsPerStep);

                if (probe !== null && !nameEquals(probe, qname)) {
                    sendName = probe;
                    sendType = PacketTypes.NS;
                    isMinimized = true;
                }
            }

            const visitKey = `${nsAddr}|${sendName}|${sendType}|${qclass}`;

            if (ctx.visited.has(visitKey)) {
                throw new Error(`RecursiveResolver: query loop detected at ${nsAddr} for ${sendName}/${sendType}`);
            }

            ctx.visited.add(visitKey);

            const response = await this._queryServer(nsAddr, sendName, sendType, qclass, ctx);
            lastResponse = response;
            this._cacheResponse(response, nsZone.zone);

            if (isMinimized) {
                // Minimized-query response handling per RFC 9156 §2.3.

                // Permissive fast path: an authoritative server is
                // allowed to fold extra data into the answer section
                // (RFC 1034 §4.3.4). If the response already contains
                // records that match the original (qname, qtype) — and
                // we asked an in-bailiwick parent — treat it as the
                // final answer. Saves a roundtrip and accommodates
                // auths that don't differentiate by what was asked.
                if (response.header.aa === 1 && response.header.rcode === RCODE.NOERROR) {
                    const direct = response.answers.some((r) =>
                        nameEquals(r.name, qname) && r.packetType.type === qtype
                    );

                    if (direct) {
                        const handled = await this._handleAnswer(response, qname, qtype, qclass, ctx);
                        return this._dnssecValidator !== null
                            ? this._dnssecValidator.finalize(handled, response, nsZone.zone, ctx)
                            : handled;
                    }
                }

                if (response.header.aa === 1 && response.header.rcode === RCODE.NXDOMAIN) {
                    // The probe name doesn't exist in the parent zone.
                    // Since the probe is an ancestor of qname, qname
                    // cannot exist either (RFC 8020 / RFC 9156 §2.3).
                    // Mirror the NXDOMAIN to the original qname so the
                    // caller and cache see the right shape.
                    this._cache.setNegative(qname, qtype, qclass, 'NXDOMAIN', negativeTtl(extractSoa(response)));
                    const built = RecursiveResolver._buildResponse(ctx, RCODE.NXDOMAIN, ctx.chain, extractSoa(response));
                    return this._dnssecValidator !== null
                        ? this._dnssecValidator.finalize(built, response, nsZone.zone, ctx)
                        : built;
                }

                // Referral wins over auth-NODATA — a server that knows
                // a delegation deeper than its own zone should still be
                // honoured even when the answer section is empty.
                const referralZoneMin = this._referralZone(response, nsZone.zone);

                if (referralZoneMin !== null) {
                    if (!isStrictlyDeeper(referralZoneMin, nsZone.zone)) {
                        throw new Error(`RecursiveResolver: non-progressing referral ${nsZone.zone} → ${referralZoneMin}`);
                    }
                    continue;
                }

                // No referral and no NXDOMAIN — the parent zone owns
                // this name and there's no delegation cut at the probe.
                // RFC 9156 §2.3: drop minimization for the next round
                // so we send the full (qname, qtype) to the same NS.
                //
                // Also covers the SERVFAIL / REFUSED fallback path (RFC
                // 9156 §3): some old auths reject NS probes outright;
                // dropping minimization and retrying with the full
                // query usually works.
                minimizationDisabled = true;
                continue;
            }

            // Authoritative answer with records.
            if (response.header.aa === 1 && response.answers.length > 0) {
                const handled = await this._handleAnswer(response, currentName, currentType, qclass, ctx);
                return this._dnssecValidator !== null
                    ? this._dnssecValidator.finalize(handled, response, nsZone.zone, ctx)
                    : handled;
            }

            // Authoritative NXDOMAIN.
            if (response.header.aa === 1 && response.header.rcode === RCODE.NXDOMAIN) {
                const built = RecursiveResolver._buildResponse(ctx, RCODE.NXDOMAIN, ctx.chain, extractSoa(response));
                return this._dnssecValidator !== null
                    ? this._dnssecValidator.finalize(built, response, nsZone.zone, ctx)
                    : built;
            }

            // Authoritative NODATA: aa, NOERROR, no answers, SOA in authority.
            if (response.header.aa === 1 && response.header.rcode === RCODE.NOERROR) {
                const built = RecursiveResolver._buildResponse(ctx, RCODE.NOERROR, ctx.chain, extractSoa(response));
                return this._dnssecValidator !== null
                    ? this._dnssecValidator.finalize(built, response, nsZone.zone, ctx)
                    : built;
            }

            // Referral — authority section carries NS records for a deeper zone.
            const referralZone = this._referralZone(response, nsZone.zone);

            if (referralZone === null) {
                // The server gave us nothing useful (bogus or empty). Try a
                // different NS for the same zone if any cached, otherwise fail.
                continue;
            }

            // Loop guard: a referral must descend strictly deeper than where we
            // currently were, or we're spinning.
            if (!isStrictlyDeeper(referralZone, nsZone.zone)) {
                throw new Error(`RecursiveResolver: non-progressing referral ${nsZone.zone} → ${referralZone}`);
            }

            // Loop continues — next iteration finds the new closest NS for `currentName`.
        }

        if (lastResponse !== null) {
            return RecursiveResolver._buildResponse(ctx, lastResponse.header.rcode, ctx.chain, []);
        }

        throw new Error('RecursiveResolver: query budget exhausted');
    }

    /**
     * Build the resolver's view of a delegation point: the deepest cached
     * NS RRset that is a suffix of `qname`, plus the matching glue we
     * already have.
     *
     * Returns `null` only when even the root NS isn't in cache, which
     * implies the resolver wasn't seeded — should not happen in normal
     * use because the constructor primes the root.
     * @protected
     */
    /** @internal */
    public _findClosestNs(qname: string, qclass: PacketClass): {zone: string; ns: PacketResource[];} | null {
        const labels = labelsOf(qname);

        for (let i = 0; i <= labels.length; i++) {
            const zone = labels.slice(i).join('.') || '.';
            const hit = this._cache.get(zone, PacketTypes.NS, qclass);

            if (hit !== null && hit.records.length > 0) {
                return {zone: zone, ns: hit.records.slice()};
            }
        }

        return null;
    }

    /**
     * Pick an A or AAAA address for any NS in the supplied delegation.
     * When glue is missing for every NS, recursively resolve the first
     * NS name's A record (RFC 1034 §5.3.3 sibling/glueless delegation).
     *
     * Prefers IPv4 in v1 because not every test harness supports v6.
     * @protected
     */
    /** @internal */
    public async _pickNsAddress(
        nsZone: {zone: string; ns: PacketResource[];},
        qclass: PacketClass,
        ctx: ResolveCtx
    ): Promise<string | null> {
        for (const r of nsZone.ns) {
            if (!(r.packetType instanceof NS)) {
                continue;
            }

            const a = this._cache.get(r.packetType.ns, PacketTypes.A, qclass);

            if (a !== null && a.records.length > 0) {
                return (a.records[0].packetType as A).address;
            }
        }

        // No A glue cached — try AAAA.
        for (const r of nsZone.ns) {
            if (!(r.packetType instanceof NS)) {
                continue;
            }

            const aaaa = this._cache.get(r.packetType.ns, PacketTypes.AAAA, qclass);

            if (aaaa !== null && aaaa.records.length > 0) {
                return (aaaa.records[0].packetType as AAAA).address;
            }
        }

        // Glueless delegation — sub-resolve the first NS's A record.
        for (const r of nsZone.ns) {
            if (!(r.packetType instanceof NS)) {
                continue;
            }

            const nsName = r.packetType.ns;

            // Skip in-bailiwick NS without glue: we'd have to query the
            // very zone we're trying to learn about — not worth the loop
            // complexity in v1. Out-of-bailiwick is fine.
            if (Bailiwick.contains(nsZone.zone, nsName)) {
                continue;
            }

            try {
                // Sub-resolution must not leak into the caller's CNAME chain
                // or its visited-set scope: same budgets, fresh chain.
                const savedChain = ctx.chain;
                const savedDepth = ctx.cnameDepth;
                ctx.chain = [];
                ctx.cnameDepth = 0;

                try {
                    await this._resolveOnce(nsName, PacketTypes.A, qclass, ctx);
                } finally {
                    ctx.chain = savedChain;
                    ctx.cnameDepth = savedDepth;
                }

                const refreshed = this._cache.get(nsName, PacketTypes.A, qclass);

                if (refreshed !== null && refreshed.records.length > 0) {
                    return (refreshed.records[0].packetType as A).address;
                }
            } catch {
                // try next NS
            }
        }

        return null;
    }

    /**
     * Send `(qname, qtype, qclass)` to `serverIp` with a randomized
     * 16-bit ID and an optional 0x20 case scramble. Verifies the
     * response's question echoes the case (RFC 5452 §9.2) before
     * returning.
     *
     * RFC 7766 §5: when the UDP response carries TC=1, the resolver
     * reissues the same question over TCP (default port 53) using the
     * configured TCP transport. The retry counts as a separate query
     * against the resolution budget and runs under the remaining
     * `timeoutMs` window. TCP failures propagate; the outer iteration
     * loop converts them to SERVFAIL via the `try/catch` in `resolve()`.
     * @protected
     */
    /** @internal */
    public async _queryServer(
        serverIp: string,
        qname: string,
        qtype: number | PacketTypes,
        qclass: PacketClass,
        ctx: ResolveCtx
    ): Promise<Packet> {
        const sentName = this._use0x20 ? Random0x20.scramble(qname) : qname;

        const query = new Packet();
        // eslint-disable-next-line no-bitwise
        query.header.id = (Math.random() * 0xFFFF) | 0;
        query.header.rd = 0; // We're iterating ourselves.
        query.questions.push(new PacketQuestion(sentName, qtype, qclass));

        if (this._useEdns) {
            // RFC 6891 §6.2.3 — advertise the UDP buffer the resolver
            // can reassemble. The TCP retry path doesn't need it (TCP
            // streams aren't size-bounded the same way) but sending the
            // OPT through TCP too is harmless and matches what real
            // recursors do.
            //
            // RFC 3225: DO=1 is required for the auth to include RRSIG
            // / NSEC / NSEC3 in the response — without it, validation
            // would reject every signed answer for missing signatures.
            //
            // If a previous response from this server advertised a
            // smaller buffer, downgrade to that — saves the server from
            // shipping a frame it knows can't fit on its side.
            const cachedBuf = this._serverBuffers.get(serverIp);
            const effectiveBuf = cachedBuf !== undefined && cachedBuf < this._udpPayloadSize
                ? cachedBuf
                : this._udpPayloadSize;
            query.additionals.push(EDNS.createResource([], effectiveBuf, this._dnssecEnabled));
        }

        const response = await this._sendAndVerify(this._transport, this._port, serverIp, query, sentName, ctx);

        if (response.header.tc === 1 && this._tcpFallback) {
            return this._sendAndVerify(this._tcpTransport, this._tcpPort, serverIp, query, sentName, ctx);
        }

        return response;
    }

    /**
     * Send `query` via `transport`, enforce the per-query deadline, and
     * verify the response's transaction ID + 0x20 case echo. Each call
     * counts as one upstream query against the resolution budget.
     * @protected
     */
    protected async _sendAndVerify(
        transport: RecursiveResolverTransport,
        port: number,
        serverIp: string,
        query: Packet,
        sentName: string,
        ctx: ResolveCtx
    ): Promise<Packet> {
        ctx.queriesIssued++;
        this._guardBudget(ctx);

        const remaining = Math.max(1, ctx.timeoutMs - (Date.now() - ctx.startTime));
        const deadline = Math.min(ctx.queryTimeoutMs, remaining);

        const q = query.questions[0];

        const response = await withTimeout(
            transport(serverIp, port, query),
            deadline,
            `query ${serverIp} for ${q.name}/${q.type}`
        );

        if (response.header.id !== query.header.id) {
            throw new Error(`RecursiveResolver: response ID mismatch from ${serverIp}`);
        }

        if (response.questions.length === 0) {
            throw new Error(`RecursiveResolver: response from ${serverIp} carried no question`);
        }

        if (this._use0x20 && !Random0x20.matches(sentName, response.questions[0].name)) {
            throw new Error(`RecursiveResolver: 0x20 case-echo mismatch from ${serverIp}`);
        }

        // RFC 6891 §6.1.2 — when the response carries an OPT, its CLASS
        // field advertises the responder's UDP reassembly buffer. Cache
        // it for subsequent queries to the same server so we don't ask
        // for more than the responder can ship.
        for (const r of response.additionals) {
            if (r.packetType.type === PacketTypes.EDNS) {
                const advertised = r.class;

                if (typeof advertised === 'number' && advertised > 0 && advertised < this._udpPayloadSize) {
                    this._serverBuffers.set(serverIp, advertised);
                }

                break;
            }
        }

        return response;
    }

    /**
     * Cache every in-bailiwick RRset from the response. Negative answers
     * (NXDOMAIN, NODATA) are also cached when an SOA is present.
     * @protected
     */
    /** @internal */
    public _cacheResponse(response: Packet, zone: string): void {
        const filtered = Bailiwick.filter(response, zone);

        // Group answers / authorities / additionals by (name, type, class).
        const groups: Map<string, PacketResource[]> = new Map();
        const all = [...filtered.answers, ...filtered.authorities, ...filtered.additionals];

        for (const r of all) {
            // Skip OPT — pseudo-record, never cached.
            if (r.packetType.type === PacketTypes.EDNS) {
                continue;
            }

            const key = `${r.name.toLowerCase()}|${r.packetType.type}|${r.class}`;
            const bucket = groups.get(key);

            if (bucket === undefined) {
                groups.set(key, [r]);
            } else {
                bucket.push(r);
            }
        }

        for (const recs of groups.values()) {
            const ttl = minTtl(recs);
            this._cache.set(recs[0].name, recs[0].packetType.type, recs[0].class, recs, ttl);
        }

        // Negative caching (RFC 2308). Only when authoritative.
        if (response.header.aa === 1 && response.questions.length > 0) {
            const q = response.questions[0];
            const soa = extractSoa(response);

            if (response.header.rcode === RCODE.NXDOMAIN) {
                const ttl = negativeTtl(soa);
                this._cache.setNegative(q.name, q.type, q.class, 'NXDOMAIN', ttl);
            } else if (response.header.rcode === RCODE.NOERROR && response.answers.length === 0) {
                const ttl = negativeTtl(soa);
                this._cache.setNegative(q.name, q.type, q.class, 'NODATA', ttl);
            }
        }
    }

    /**
     * Process a positive authoritative answer. May follow a CNAME chain
     * by recursing — the chain accumulates in `ctx.chain`.
     * @protected
     */
    protected async _handleAnswer(
        response: Packet,
        qname: string,
        qtype: number | PacketTypes,
        qclass: PacketClass,
        ctx: ResolveCtx
    ): Promise<Packet> {
        // First, look for a direct match on (qname, qtype).
        const direct = response.answers.filter((r) =>
            nameEquals(r.name, qname) && r.packetType.type === qtype
        );

        if (direct.length > 0) {
            ctx.chain.push(...direct);
            return RecursiveResolver._buildResponse(ctx, RCODE.NOERROR, ctx.chain, []);
        }

        // No direct match — look for a CNAME at qname.
        const cname = response.answers.find((r) =>
            nameEquals(r.name, qname)
            && (r.packetType instanceof CNAME || r.packetType instanceof DNAME)
        );

        if (cname !== undefined && qtype !== PacketTypes.CNAME) {
            ctx.chain.push(cname);
            ctx.cnameDepth++;

            if (ctx.cnameDepth > ctx.maxCnameDepth) {
                throw new Error(`RecursiveResolver: CNAME chain exceeded ${ctx.maxCnameDepth} hops`);
            }

            const targetName = cname.packetType instanceof CNAME
                ? cname.packetType.domain
                : (cname.packetType as DNAME).target;

            // Some servers include the chained answer in the same response —
            // fold those in as a shortcut before recursing.
            for (const a of response.answers) {
                if (nameEquals(a.name, targetName) && a.packetType.type === qtype) {
                    ctx.chain.push(a);
                    return RecursiveResolver._buildResponse(ctx, RCODE.NOERROR, ctx.chain, []);
                }
            }

            return this._resolveOnce(targetName, qtype, qclass, ctx);
        }

        // Authoritative answer that didn't match — treat as NODATA.
        return RecursiveResolver._buildResponse(ctx, RCODE.NOERROR, ctx.chain, extractSoa(response));
    }

    /**
     * Follow a CNAME chain that's already in cache.
     * @protected
     */
    protected async _followCnameFromCache(
        qname: string,
        qtype: number | PacketTypes,
        qclass: PacketClass,
        ctx: ResolveCtx,
        cnameRecords: PacketResource[]
    ): Promise<Packet> {
        ctx.chain.push(...cnameRecords);
        ctx.cnameDepth++;

        if (ctx.cnameDepth > ctx.maxCnameDepth) {
            throw new Error(`RecursiveResolver: CNAME chain exceeded ${ctx.maxCnameDepth} hops`);
        }

        const target = (cnameRecords[0].packetType as CNAME).domain;
        return this._resolveOnce(target, qtype, qclass, ctx);
    }

    /**
     * Inspect a non-authoritative response for an NS RRset that descends
     * deeper than `currentZone`. Returns the new zone name or `null` if
     * the response is not a referral.
     * @protected
     */
    protected _referralZone(response: Packet, currentZone: string): string | null {
        let candidate: string | null = null;

        for (const r of response.authorities) {
            if (!(r.packetType instanceof NS)) {
                continue;
            }

            if (candidate === null) {
                candidate = r.name;
            } else if (!nameEquals(r.name, candidate)) {
                // Multiple zones in one authority section is suspect — bail.
                return null;
            }
        }

        if (candidate === null) {
            return null;
        }

        return isStrictlyDeeper(candidate, currentZone) ? candidate : null;
    }

    /**
     * Throw when the resolution has exceeded its overall time or query
     * budget.
     * @protected
     */
    protected _guardBudget(ctx: ResolveCtx): void {
        if (Date.now() - ctx.startTime > ctx.timeoutMs) {
            throw new Error(`RecursiveResolver: total timeout (${ctx.timeoutMs}ms)`);
        }

        if (ctx.queriesIssued >= ctx.maxQueries) {
            throw new Error(`RecursiveResolver: max queries (${ctx.maxQueries})`);
        }
    }

    /**
     * Kick off an asynchronous re-resolution of `(qname, qtype, qclass)`
     * to refresh a stale cache entry under RFC 8767 serve-stale.
     *
     * The refresh runs through the full iterative loop (`bypassCache:
     * true` so it doesn't immediately return the stale entry it's
     * meant to replace), populates the cache via the normal
     * `_cacheResponse` path on success, and silently swallows any
     * upstream errors — the caller has already received the stale
     * answer and we don't want a transient failure to surface.
     *
     * In-flight refreshes are tracked in `_refreshInFlight` so the
     * second of two near-simultaneous stale hits doesn't kick off a
     * duplicate.
     *
     * @param {string} qname
     * @param {number|PacketTypes} qtype
     * @param {PacketClass} qclass
     * @protected
     */
    protected _scheduleRefresh(qname: string, qtype: number | PacketTypes, qclass: PacketClass): void {
        const key = `${qname.toLowerCase()}|${qtype}|${qclass}`;

        if (this._refreshInFlight.has(key)) {
            return;
        }

        this._refreshInFlight.add(key);

        const refreshCtx: ResolveCtx = {
            startTime: Date.now(),
            timeoutMs: this._timeoutMs,
            queryTimeoutMs: this._queryTimeoutMs,
            maxQueries: this._maxQueries,
            maxCnameDepth: this._maxCnameDepth,
            queriesIssued: 0,
            cnameDepth: 0,
            chain: [],
            visited: new Set(),
            originalQname: qname,
            originalQtype: qtype,
            qclass: qclass,
            bypassCache: true
        };

        this._resolveOnce(qname, qtype, qclass, refreshCtx).then(
            () => this._refreshInFlight.delete(key),
            () => this._refreshInFlight.delete(key)
        );
    }

    /* ---------------------------------------------------------------- */
    /*  Static helpers                                                   */
    /* ---------------------------------------------------------------- */

    /**
     * Construct the recursor's response packet for the original
     * `(qname, qtype, qclass)`. The header mirrors a typical recursive
     * server — `qr=1`, `ra=1`, `aa=0`. Stays a static method on the
     * resolver because it depends on the private `ResolveCtx` shape.
     * @protected
     */
    protected static _buildResponse(
        ctx: ResolveCtx,
        rcode: number,
        answers: PacketResource[],
        authorities: PacketResource[]
    ): Packet {
        const out = new Packet();
        out.header.qr = 1;
        out.header.ra = 1;
        out.header.aa = 0;
        out.header.rcode = rcode;
        out.questions.push(new PacketQuestion(ctx.originalQname, ctx.originalQtype, ctx.qclass));
        out.answers = answers.slice();
        out.authorities = authorities.slice();
        return out;
    }

    /**
     * Synthesize a recursor response from a cache hit. When the cache
     * hit is the final step of a CNAME chain, `ctx.chain` already
     * carries the preceding CNAME records and the final answer is
     * appended on top of them.
     * @protected
     */
    protected static _cacheEntryToResponse(ctx: ResolveCtx, entry: {records: PacketResource[]; rcode: 'NOERROR' | 'NXDOMAIN' | 'NODATA';}): Packet {
        if (entry.rcode === 'NXDOMAIN') {
            return RecursiveResolver._buildResponse(ctx, RCODE.NXDOMAIN, ctx.chain, []);
        }

        if (entry.rcode === 'NODATA') {
            return RecursiveResolver._buildResponse(ctx, RCODE.NOERROR, ctx.chain, []);
        }

        return RecursiveResolver._buildResponse(ctx, RCODE.NOERROR, [...ctx.chain, ...entry.records], []);
    }

}

/**
 * Per-resolution scratch state. Exported for `DnssecValidator` so it
 * can pass an `inAuthChain`-flagged sub-context into the resolver's
 * own DNSKEY/DS sub-resolutions; not part of the stable public API.
 *
 * @internal
 */
export type ResolveCtx = {
    startTime: number;
    timeoutMs: number;
    queryTimeoutMs: number;
    maxQueries: number;
    maxCnameDepth: number;
    queriesIssued: number;
    cnameDepth: number;
    chain: PacketResource[];
    visited: Set<string>;
    originalQname: string;
    originalQtype: number | PacketTypes;
    qclass: PacketClass;

    /**
     * Set during authentication-chain walks to disable nested DNSSEC
     * validation — the DNSKEY/DS sub-queries used to build the chain
     * must not themselves be DNSSEC-validated (would recurse forever).
     */
    inAuthChain?: boolean;

    /**
     * Set on the ctx of an asynchronous serve-stale refresh — the
     * background resolution that runs while a stale answer is being
     * returned to the original caller. Forces `_resolveOnce` to skip
     * its cache lookup so the refresh actually hits the upstream
     * chain instead of seeing the still-cached stale entry and
     * returning that.
     */
    bypassCache?: boolean;
};