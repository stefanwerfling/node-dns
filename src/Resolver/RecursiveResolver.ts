import dgram from 'dgram';
import tcp from 'net';
import {Bailiwick} from '../Lib/Bailiwick.js';
import {DnssecVerifyOptions} from '../Lib/Dnssec.js';
import {Random0x20} from '../Lib/Random0x20.js';
import {SocketReader} from '../Lib/SocketReader.js';
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
import {DS} from '../Packet/Types/DS.js';
import {NS} from '../Packet/Types/NS.js';
import {SOA} from '../Packet/Types/SOA.js';
import {DnsCache} from './DnsCache.js';
import {DnssecChain, DnssecValidity} from './DnssecChain.js';
import {NegativeProof} from './NegativeProof.js';
import {RootHints, RootServer} from './RootHints.js';
import {TrustAnchor, TrustAnchors} from './TrustAnchor.js';

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

/**
 * DNSSEC mode. `permissive` accepts insecure zones (no DS at parent
 * proven via NSEC/NSEC3) and only fails closed on `bogus`. `strict`
 * also rejects answers whose chain cannot be authenticated end-to-end
 * — appropriate when the deployment policy requires every secure
 * answer be DNSSEC-validated.
 */
export type DnssecMode = 'strict' | 'permissive';

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
 *  - **No DNSSEC validation.** RRSIG/DNSKEY records pass through the
 *    cache untouched but are not verified against a trust anchor. A
 *    follow-up commit will plug the existing `Lib/Dnssec` validator
 *    into the response path and add NXDOMAIN/NODATA proof composition.
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
     * @protected
     */
    protected _udpPayloadSize: number;

    /**
     * @protected
     */
    protected _dnssecEnabled: boolean;

    /**
     * @protected
     */
    protected _trustAnchors: ReadonlyArray<TrustAnchor>;

    /**
     * @protected
     */
    protected _dnssecMode: DnssecMode;

    /**
     * @protected
     */
    protected _dnssecVerifyOptions: DnssecVerifyOptions;

    /**
     * Per-zone authentication state: each entry caches the validity of
     * a zone's DNSKEY set and, when `secure`, the keys themselves so
     * answer-RRset validation can reuse them.
     * @protected
     */
    protected _zoneSecurity: Map<string, ZoneSecurity>;

    /**
     * @param {RecursiveResolverOptions} options
     */
    public constructor(options: RecursiveResolverOptions = {}) {
        this._cache = options.cache ?? new DnsCache();
        this._transport = options.transport ?? RecursiveResolver._defaultUdpTransport;
        this._use0x20 = options.use0x20 ?? true;
        this._timeoutMs = options.timeoutMs ?? 10_000;
        this._queryTimeoutMs = options.queryTimeoutMs ?? 2_000;
        this._maxQueries = options.maxQueries ?? 50;
        this._maxCnameDepth = options.maxCnameDepth ?? 16;
        this._port = options.port ?? 53;
        this._tcpFallback = options.tcpFallback ?? true;
        this._tcpPort = options.tcpPort ?? 53;
        this._tcpTransport = options.tcpTransport ?? RecursiveResolver._defaultTcpTransport;
        this._useEdns = options.useEdns ?? true;
        this._udpPayloadSize = options.udpPayloadSize ?? 4096;

        const dnssecOpt = options.dnssec;
        this._dnssecEnabled = dnssecOpt !== undefined && dnssecOpt !== false;

        const dnssecObj = typeof dnssecOpt === 'object' ? dnssecOpt : {};
        this._trustAnchors = dnssecObj.trustAnchors ?? TrustAnchors.DEFAULT;
        this._dnssecMode = dnssecObj.mode ?? 'permissive';
        this._dnssecVerifyOptions = dnssecObj.verifyOptions ?? {};
        this._zoneSecurity = new Map();

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
    protected async _resolveOnce(
        qname: string,
        qtype: number | PacketTypes,
        qclass: PacketClass,
        ctx: ResolveCtx
    ): Promise<Packet> {
        // Direct cache hit on the requested (qname, qtype)?
        const direct = this._cache.get(qname, qtype, qclass);

        if (direct !== null) {
            return RecursiveResolver._cacheEntryToResponse(ctx, direct);
        }

        // Cached CNAME at qname → follow it (when qtype isn't CNAME itself).
        if (qtype !== PacketTypes.CNAME) {
            const cnameHit = this._cache.get(qname, PacketTypes.CNAME, qclass);

            if (cnameHit !== null && cnameHit.records.length > 0) {
                return this._followCnameFromCache(qname, qtype, qclass, ctx, cnameHit.records);
            }
        }

        // Iterative resolution loop.
        let currentName = qname;
        let currentType = qtype;
        let lastResponse: Packet | null = null;

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

            const visitKey = `${nsAddr}|${currentName}|${currentType}|${qclass}`;

            if (ctx.visited.has(visitKey)) {
                throw new Error(`RecursiveResolver: query loop detected at ${nsAddr} for ${currentName}/${currentType}`);
            }

            ctx.visited.add(visitKey);

            const response = await this._queryServer(nsAddr, currentName, currentType, qclass, ctx);
            lastResponse = response;
            this._cacheResponse(response, nsZone.zone);

            // Authoritative answer with records.
            if (response.header.aa === 1 && response.answers.length > 0) {
                const handled = await this._handleAnswer(response, currentName, currentType, qclass, ctx);
                return this._dnssecFinalize(handled, response, nsZone.zone, ctx);
            }

            // Authoritative NXDOMAIN.
            if (response.header.aa === 1 && response.header.rcode === RCODE.NXDOMAIN) {
                const built = RecursiveResolver._buildResponse(ctx, RCODE.NXDOMAIN, ctx.chain, RecursiveResolver._extractSoa(response));
                return this._dnssecFinalize(built, response, nsZone.zone, ctx);
            }

            // Authoritative NODATA: aa, NOERROR, no answers, SOA in authority.
            if (response.header.aa === 1 && response.header.rcode === RCODE.NOERROR) {
                const built = RecursiveResolver._buildResponse(ctx, RCODE.NOERROR, ctx.chain, RecursiveResolver._extractSoa(response));
                return this._dnssecFinalize(built, response, nsZone.zone, ctx);
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
            if (!RecursiveResolver._isStrictlyDeeper(referralZone, nsZone.zone)) {
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
    protected _findClosestNs(qname: string, qclass: PacketClass): {zone: string; ns: PacketResource[];} | null {
        const labels = RecursiveResolver._labels(qname);

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
    protected async _pickNsAddress(
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
    protected async _queryServer(
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
            query.additionals.push(EDNS.createResource([], this._udpPayloadSize, this._dnssecEnabled));
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

        const response = await RecursiveResolver._withTimeout(
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

        return response;
    }

    /**
     * Cache every in-bailiwick RRset from the response. Negative answers
     * (NXDOMAIN, NODATA) are also cached when an SOA is present.
     * @protected
     */
    protected _cacheResponse(response: Packet, zone: string): void {
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
            const ttl = RecursiveResolver._minTtl(recs);
            this._cache.set(recs[0].name, recs[0].packetType.type, recs[0].class, recs, ttl);
        }

        // Negative caching (RFC 2308). Only when authoritative.
        if (response.header.aa === 1 && response.questions.length > 0) {
            const q = response.questions[0];
            const soa = RecursiveResolver._extractSoa(response);

            if (response.header.rcode === RCODE.NXDOMAIN) {
                const ttl = RecursiveResolver._negativeTtl(soa);
                this._cache.setNegative(q.name, q.type, q.class, 'NXDOMAIN', ttl);
            } else if (response.header.rcode === RCODE.NOERROR && response.answers.length === 0) {
                const ttl = RecursiveResolver._negativeTtl(soa);
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
            RecursiveResolver._nameEquals(r.name, qname) && r.packetType.type === qtype
        );

        if (direct.length > 0) {
            ctx.chain.push(...direct);
            return RecursiveResolver._buildResponse(ctx, RCODE.NOERROR, ctx.chain, []);
        }

        // No direct match — look for a CNAME at qname.
        const cname = response.answers.find((r) =>
            RecursiveResolver._nameEquals(r.name, qname)
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
                if (RecursiveResolver._nameEquals(a.name, targetName) && a.packetType.type === qtype) {
                    ctx.chain.push(a);
                    return RecursiveResolver._buildResponse(ctx, RCODE.NOERROR, ctx.chain, []);
                }
            }

            return this._resolveOnce(targetName, qtype, qclass, ctx);
        }

        // Authoritative answer that didn't match — treat as NODATA.
        return RecursiveResolver._buildResponse(ctx, RCODE.NOERROR, ctx.chain, RecursiveResolver._extractSoa(response));
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
            } else if (!RecursiveResolver._nameEquals(r.name, candidate)) {
                // Multiple zones in one authority section is suspect — bail.
                return null;
            }
        }

        if (candidate === null) {
            return null;
        }

        return RecursiveResolver._isStrictlyDeeper(candidate, currentZone) ? candidate : null;
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

    /* ---------------------------------------------------------------- */
    /*  DNSSEC validation pipeline                                       */
    /* ---------------------------------------------------------------- */

    /**
     * Apply DNSSEC validation to a response and adjust the AD bit /
     * rcode accordingly. No-op when DNSSEC is disabled or the call is
     * inside an auth-chain sub-resolution (would recurse forever).
     *
     * The validator inspects the *raw* server response (`rawResponse`)
     * because that's where the RRSIG records live — `builtResponse`
     * has already been filtered down to the question's answer plus
     * any CNAME chain, so any RRSIGs at the answer's owner name have
     * been stripped. The AD bit is written onto `builtResponse` so the
     * caller's view matches the answer.
     *
     * @param {Packet} builtResponse the resolver's view-of-truth response
     * @param {Packet} rawResponse the wire response from the auth server
     * @param {string} signingZone zone the response is authoritative for
     * @param {ResolveCtx} ctx
     * @return {Promise<Packet>}
     * @protected
     */
    protected async _dnssecFinalize(
        builtResponse: Packet,
        rawResponse: Packet,
        signingZone: string,
        ctx: ResolveCtx
    ): Promise<Packet> {
        if (!this._dnssecEnabled || ctx.inAuthChain) {
            return builtResponse;
        }

        const validity = await this._validateResponse(rawResponse, signingZone, ctx);

        if (validity === 'bogus') {
            // RFC 4035 §5.5: a bogus answer surfaces as SERVFAIL.
            return RecursiveResolver._buildResponse(ctx, RCODE.SERVFAIL, [], []);
        }

        if (validity === 'insecure' && this._dnssecMode === 'strict') {
            return RecursiveResolver._buildResponse(ctx, RCODE.SERVFAIL, [], []);
        }

        // RFC 4035 §3.2 carved AD (Authentic Data) and CD (Checking
        // Disabled) out of the legacy 3-bit Z field. Bit layout (MSB
        // first): Z, AD, CD. Set AD on validated answers; clear it
        // otherwise.
        // eslint-disable-next-line no-bitwise, no-param-reassign
        builtResponse.header.z = validity === 'secure'
            // eslint-disable-next-line no-bitwise
            ? builtResponse.header.z | 0b010
            // eslint-disable-next-line no-bitwise
            : builtResponse.header.z & ~0b010;
        return builtResponse;
    }

    /**
     * Authenticate every signed RRset in the response and, for negative
     * answers, the NSEC/NSEC3 proof. Returns the overall validity:
     *
     *  - `secure` — every signed RRset verified, negative proof (if any) verified
     *  - `insecure` — chain proves no DS exists at the answer's signing zone
     *  - `bogus` — at least one signature didn't verify, or a proof was missing
     *  - `indeterminate` — no anchor covers the zone (resolver passes through)
     *
     * @param {Packet} response
     * @param {string} signingZone
     * @param {ResolveCtx} ctx
     * @return {Promise<DnssecValidity>}
     * @protected
     */
    protected async _validateResponse(
        response: Packet,
        signingZone: string,
        ctx: ResolveCtx
    ): Promise<DnssecValidity> {
        const zoneState = await this._authenticateZone(signingZone, ctx);

        if (zoneState.validity !== 'secure') {
            return zoneState.validity;
        }

        const dnskeys = zoneState.dnskeys ?? [];

        // Validate every (non-RRSIG, non-OPT) RRset in the answer + authority.
        const sections = [...response.answers, ...response.authorities];
        const groups = DnssecChain.groupRrsets(sections);
        const rrsigs = DnssecChain.rrsigs(sections);

        for (const [, recs] of groups) {
            const owner = recs[0].name;
            const matchingSigs = DnssecChain.rrsigsFor(rrsigs, owner, recs[0].packetType.type);

            if (matchingSigs.length === 0) {
                // Some sections (e.g. CNAME chains in mixed responses)
                // may not be signed in the same response; the resolver
                // sees only what the auth shipped. Treat as insecure for
                // permissive mode — strict mode escalates upstream.
                continue;
            }

            const r = DnssecChain.validateRrset(owner, recs, matchingSigs, dnskeys, this._dnssecVerifyOptions);

            if (r.validity === 'bogus') {
                return 'bogus';
            }
        }

        // Negative-proof validation for NXDOMAIN / NODATA shapes.
        if (response.header.rcode === RCODE.NXDOMAIN || (response.header.rcode === RCODE.NOERROR && response.answers.length === 0)) {
            const nsec = response.authorities.filter((r) => r.packetType.type === PacketTypes.NSEC);
            const nsec3 = response.authorities.filter((r) => r.packetType.type === PacketTypes.NSEC3);

            const qname = response.questions[0]?.name ?? ctx.originalQname;
            const qtype = response.questions[0]?.type ?? ctx.originalQtype;

            if (response.header.rcode === RCODE.NXDOMAIN) {
                const proven = (nsec.length > 0 && NegativeProof.verifyNxdomainNsec(qname, signingZone, nsec))
                    || (nsec3.length > 0 && NegativeProof.verifyNxdomainNsec3(qname, signingZone, nsec3));

                if (!proven) {
                    return 'bogus';
                }
            } else {
                const proven = (nsec.length > 0 && NegativeProof.verifyNodataNsec(qname, qtype as number, nsec))
                    || (nsec3.length > 0 && NegativeProof.verifyNodataNsec3(qname, qtype as number, signingZone, nsec3));

                if (nsec.length + nsec3.length > 0 && !proven) {
                    return 'bogus';
                }
            }
        }

        return 'secure';
    }

    /**
     * Walk the DNSSEC chain from a configured trust anchor down to
     * `zone`, fetching DNSKEY + DS records at each step and validating
     * them. Caches the result in `_zoneSecurity` so subsequent answers
     * within the same zone re-use the authenticated DNSKEY set.
     *
     * The walk runs *inside* an existing `ResolveCtx`, with
     * `inAuthChain: true` so the sub-resolutions for DNSKEY/DS aren't
     * themselves DNSSEC-validated (would recurse forever).
     *
     * @param {string} zone
     * @param {ResolveCtx} ctx
     * @return {Promise<ZoneSecurity>}
     * @protected
     */
    protected async _authenticateZone(zone: string, ctx: ResolveCtx): Promise<ZoneSecurity> {
        const norm = RecursiveResolver._normZone(zone);
        const cached = this._zoneSecurity.get(norm);

        if (cached !== undefined) {
            return cached;
        }

        const anchor = TrustAnchors.findFor(this._trustAnchors, zone);

        if (anchor === undefined) {
            const out: ZoneSecurity = {validity: 'indeterminate', reason: 'no trust anchor covers zone'};
            this._zoneSecurity.set(norm, out);
            return out;
        }

        // Path from anchor down to zone, e.g. ['', 'com', 'example.com'].
        const path = RecursiveResolver._chainPath(anchor.zone, zone);
        let parentDsList: DS[] = [anchor.ds as DS];

        const subCtx: ResolveCtx = {...ctx, inAuthChain: true};

        let result: ZoneSecurity = {validity: 'indeterminate'};

        for (let i = 0; i < path.length; i++) {
            const step = path[i];
            const stepNorm = RecursiveResolver._normZone(step);
            const stepCached = this._zoneSecurity.get(stepNorm);

            if (stepCached?.validity === 'secure') {
                result = stepCached;

                // Continue chain with this zone's DNSKEYs.
                if (i + 1 < path.length) {
                    const dsResult = await this._fetchAndValidateDs(path[i + 1], stepCached.dnskeys ?? [], subCtx);

                    if (dsResult.kind === 'secure') {
                        parentDsList = dsResult.ds;
                        continue;
                    }

                    if (dsResult.kind === 'insecure') {
                        const insec: ZoneSecurity = {validity: 'insecure', reason: dsResult.reason};
                        this._zoneSecurity.set(RecursiveResolver._normZone(path[i + 1]), insec);

                        if (RecursiveResolver._normZone(path[i + 1]) === norm) {
                            return insec;
                        }

                        return insec;
                    }

                    const bogus: ZoneSecurity = {validity: 'bogus', reason: dsResult.reason};
                    this._zoneSecurity.set(RecursiveResolver._normZone(path[i + 1]), bogus);
                    return bogus;
                }

                continue;
            }

            if (stepCached?.validity === 'bogus' || stepCached?.validity === 'insecure') {
                return stepCached;
            }

            // Fetch + validate the DNSKEY RRset of `step`. The
            // sub-resolve answer-shape filters down to (qname, qtype),
            // dropping RRSIGs — but `_cacheResponse` already grouped
            // and cached every RRset separately, including RRSIGs at
            // the zone apex. Pull them from the cache instead.
            try {
                await this._resolveOnce(step, PacketTypes.DNSKEY, PacketClass.IN, subCtx);
            } catch (e) {
                const bogus: ZoneSecurity = {validity: 'bogus', reason: `failed to fetch DNSKEY for ${step}`};
                this._zoneSecurity.set(stepNorm, bogus);
                return bogus;
            }

            const dnskeyEntry = this._cache.get(step, PacketTypes.DNSKEY, PacketClass.IN);
            const rrsigEntry = this._cache.get(step, PacketTypes.RRSIG, PacketClass.IN);
            const dnskeys = dnskeyEntry?.records ?? [];
            const dnskeyRrsigs = DnssecChain.rrsigsFor(rrsigEntry?.records ?? [], step, PacketTypes.DNSKEY);

            const validated = DnssecChain.validateDnskeyRrset(
                step,
                dnskeys,
                dnskeyRrsigs,
                parentDsList,
                this._dnssecVerifyOptions
            );

            if (validated.validity !== 'secure') {
                const bogus: ZoneSecurity = {validity: 'bogus', reason: validated.reason ?? 'DNSKEY validation failed'};
                this._zoneSecurity.set(stepNorm, bogus);
                return bogus;
            }

            const stepSec: ZoneSecurity = {validity: 'secure', dnskeys: dnskeys, rrsigs: dnskeyRrsigs};
            this._zoneSecurity.set(stepNorm, stepSec);
            result = stepSec;

            // For the next step, fetch + validate its DS record.
            if (i + 1 < path.length) {
                const dsResult = await this._fetchAndValidateDs(path[i + 1], dnskeys, subCtx);

                if (dsResult.kind === 'secure') {
                    parentDsList = dsResult.ds;
                    continue;
                }

                if (dsResult.kind === 'insecure') {
                    const insec: ZoneSecurity = {validity: 'insecure', reason: dsResult.reason};
                    this._zoneSecurity.set(RecursiveResolver._normZone(path[i + 1]), insec);
                    return insec;
                }

                const bogus: ZoneSecurity = {validity: 'bogus', reason: dsResult.reason};
                this._zoneSecurity.set(RecursiveResolver._normZone(path[i + 1]), bogus);
                return bogus;
            }
        }

        return result;
    }

    /**
     * Fetch the DS RRset at `zone` (queried against the parent zone)
     * and validate its signature with the parent's DNSKEY set. Returns
     * a discriminated outcome:
     *
     *  - `secure` — DS validates, returns the DS records for chain continuation
     *  - `insecure` — parent NOERRORed with no DS (insecure delegation)
     *  - `bogus` — DS query failed, or the DS RRset's RRSIG didn't verify
     *
     * @param {string} zone
     * @param {PacketResource[]} parentDnskeys
     * @param {ResolveCtx} ctx (already in auth-chain mode)
     * @return {Promise<{kind: 'secure'; ds: DS[];} | {kind: 'insecure' | 'bogus'; reason?: string;}>}
     * @protected
     */
    protected async _fetchAndValidateDs(
        zone: string,
        parentDnskeys: PacketResource[],
        ctx: ResolveCtx
    ): Promise<{kind: 'secure'; ds: DS[];} | {kind: 'insecure' | 'bogus'; reason?: string;}> {
        // DS records live in the *parent* zone (RFC 4035 §5.2), so the
        // normal NS-chasing path is wrong — it would terminate at the
        // child's own NS and never see the DS. Query the closest NS
        // that is strictly above `zone` instead.
        let dsResp: Packet;

        try {
            dsResp = await this._queryDsAtParent(zone, ctx);
        } catch (e) {
            return {kind: 'bogus', reason: `failed to fetch DS for ${zone}`};
        }

        // `_cacheResponse` grouped the DS RRset and its RRSIGs into
        // separate cache entries keyed by (name, type). Read them
        // from there rather than from `dsResp.answers`, which only
        // contains the (qname, qtype) match.
        const dsEntry = this._cache.get(zone, PacketTypes.DS, PacketClass.IN);
        const rrsigEntry = this._cache.get(zone, PacketTypes.RRSIG, PacketClass.IN);

        const dsRecords = dsEntry?.records ?? [];
        const dsRrsigs = DnssecChain.rrsigsFor(rrsigEntry?.records ?? [], zone, PacketTypes.DS);

        if (dsRecords.length === 0) {
            if (dsResp.header.rcode === RCODE.NOERROR) {
                return {kind: 'insecure', reason: 'no DS record (insecure delegation)'};
            }

            return {kind: 'bogus', reason: 'DS query did not return NOERROR'};
        }

        const validated = DnssecChain.validateRrset(
            zone,
            dsRecords,
            dsRrsigs,
            parentDnskeys,
            this._dnssecVerifyOptions
        );

        if (validated.validity !== 'secure') {
            return {kind: 'bogus', reason: validated.reason ?? 'DS RRset signature did not verify'};
        }

        return {kind: 'secure', ds: dsRecords.map((r) => r.packetType as DS)};
    }

    /**
     * Send a `DS` query for `zone` to the closest NS that is strictly
     * above `zone` — i.e. the parent zone's authority. RFC 4035 §5.2:
     * DS records live at the parent, not the zone itself.
     *
     * Bypasses the normal iterative loop because that loop would pick
     * `zone`'s own NS as the closest match (the referral that delivered
     * `zone` already cached its NS RRset).
     *
     * @param {string} zone
     * @param {ResolveCtx} ctx
     * @return {Promise<Packet>}
     * @protected
     */
    protected async _queryDsAtParent(zone: string, ctx: ResolveCtx): Promise<Packet> {
        const parent = RecursiveResolver._parentOf(zone);
        const ns = this._findClosestNs(parent, PacketClass.IN);

        if (ns === null) {
            throw new Error(`RecursiveResolver: no cached NS for parent of ${zone}`);
        }

        // Skip the cache entry of `zone` itself even if it sneaks in:
        // walk one step up if the closest NS turned out to BE `zone`.
        const stableNs = RecursiveResolver._isStrictlyDeeper(ns.zone, parent) || ns.zone === RecursiveResolver._normZone(zone) || ns.zone === zone
            ? this._findClosestNs(RecursiveResolver._parentOf(ns.zone), PacketClass.IN)
            : ns;

        if (stableNs === null) {
            throw new Error(`RecursiveResolver: no usable parent NS for ${zone}`);
        }

        const addr = await this._pickNsAddress(stableNs, PacketClass.IN, ctx);

        if (addr === null) {
            throw new Error(`RecursiveResolver: no usable address for parent NS of ${zone}`);
        }

        const response = await this._queryServer(addr, zone, PacketTypes.DS, PacketClass.IN, ctx);
        this._cacheResponse(response, stableNs.zone);
        return response;
    }

    /* ---------------------------------------------------------------- */
    /*  Static helpers                                                   */
    /* ---------------------------------------------------------------- */

    /**
     * The parent zone of `zone` — strip the leftmost label. The parent
     * of the root is the root itself (no further to ascend).
     * @param {string} zone
     * @return {string}
     * @protected
     */
    protected static _parentOf(zone: string): string {
        const norm = RecursiveResolver._normZone(zone);

        if (norm === '') {
            return '.';
        }

        const dot = norm.indexOf('.');

        if (dot === -1) {
            return '.';
        }

        return norm.slice(dot + 1);
    }

    /**
     * Default UDP transport. One-shot dgram socket per query — no
     * connection reuse in v1 (recursors typically batch via a connection
     * pool; that's a future commit).
     * @protected
     */
    protected static _defaultUdpTransport(
        serverIp: string,
        port: number,
        query: Packet
    ): Promise<Packet> {
        return new Promise((resolve, reject) => {
            const family = serverIp.includes(':') ? 'udp6' : 'udp4';
            const socket = dgram.createSocket(family);
            let settled = false;

            const finish = (err: Error | null, packet?: Packet): void => {
                if (settled) {
                    return;
                }

                settled = true;

                try {
                    socket.close();
                } catch {
                    /* socket may already be closed */
                }

                if (err) {
                    reject(err);
                } else {
                    resolve(packet!);
                }
            };

            socket.once('message', (msg) => {
                try {
                    finish(null, Packet.parse(msg));
                } catch (err) {
                    finish(err instanceof Error ? err : new Error(String(err)));
                }
            });

            socket.once('error', (err) => finish(err));

            socket.send(query.toBuffer(), port, serverIp, (err) => {
                if (err) {
                    finish(err);
                }
            });
        });
    }

    /**
     * Default TCP transport for the TC=1 retry path (RFC 7766). One-shot
     * length-prefixed connection per query — no connection pooling in
     * v1. Returns the parsed `Packet`.
     * @protected
     */
    protected static _defaultTcpTransport(
        serverIp: string,
        port: number,
        query: Packet
    ): Promise<Packet> {
        return new Promise((resolve, reject) => {
            const socket = tcp.createConnection({host: serverIp, port: port});
            let settled = false;

            const finish = (err: Error | null, packet?: Packet): void => {
                if (settled) {
                    return;
                }

                settled = true;

                try {
                    socket.destroy();
                } catch {
                    /* socket may already be closed */
                }

                if (err) {
                    reject(err);
                } else {
                    resolve(packet!);
                }
            };

            socket.once('connect', () => {
                const message = query.toBuffer();
                const len = Buffer.alloc(2);
                len.writeUInt16BE(message.length);
                socket.write(Buffer.concat([len, message]));
            });

            SocketReader.readStream(socket).then(
                (data) => {
                    try {
                        finish(null, Packet.parse(data));
                    } catch (err) {
                        finish(err instanceof Error ? err : new Error(String(err)));
                    }
                },
                (err) => finish(err)
            );
        });
    }

    /**
     * Race a promise against a timeout — used to cap individual query
     * waits.
     * @protected
     */
    protected static _withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
        return new Promise<T>((resolve, reject) => {
            const timer = setTimeout(() => {
                reject(new Error(`RecursiveResolver: timeout after ${ms}ms (${label})`));
            }, ms);

            promise.then(
                (value) => {
                    clearTimeout(timer);
                    resolve(value);
                },
                (err) => {
                    clearTimeout(timer);
                    reject(err);
                }
            );
        });
    }

    /**
     * Construct the recursor's response packet for the original
     * `(qname, qtype, qclass)`. The header mirrors a typical recursive
     * server — `qr=1`, `ra=1`, `aa=0`.
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

    /**
     * RFC 1035 §3.7 — TTL of an RRset is the minimum of its records'
     * TTLs. Implementations sometimes cheat and use the max; the
     * conservative choice is min.
     * @protected
     */
    protected static _minTtl(records: PacketResource[]): number {
        let min = Infinity;

        for (const r of records) {
            if (r.ttl < min) {
                min = r.ttl;
            }
        }

        return Number.isFinite(min) ? min : 0;
    }

    /**
     * RFC 2308 §5 — a negative answer's TTL is the SOA MINIMUM (or the
     * SOA's own TTL, whichever is smaller). Defaults to 0 when no SOA
     * is supplied (the entry won't be cached effectively).
     * @protected
     */
    protected static _negativeTtl(soa: PacketResource[]): number {
        if (soa.length === 0) {
            return 0;
        }

        const r = soa[0];

        if (!(r.packetType instanceof SOA)) {
            return 0;
        }

        return Math.min(r.packetType.minimum, r.ttl);
    }

    /**
     * Extract SOA records from an authority section, if any.
     * @protected
     */
    protected static _extractSoa(packet: Packet): PacketResource[] {
        return packet.authorities.filter((r) => r.packetType instanceof SOA);
    }

    /**
     * Split a name into labels. Trailing dot is dropped.
     * @protected
     */
    protected static _labels(name: string): string[] {
        if (name === '.' || name === '') {
            return [];
        }

        const stripped = name.endsWith('.') ? name.slice(0, -1) : name;
        return stripped.split('.');
    }

    /**
     * Case-insensitive name compare with trailing-dot tolerance.
     * @protected
     */
    protected static _nameEquals(a: string, b: string): boolean {
        const norm = (n: string): string => {
            const stripped = n.endsWith('.') && n.length > 1 ? n.slice(0, -1) : n;
            return stripped.toLowerCase();
        };

        return norm(a) === norm(b);
    }

    /**
     * Normalize a zone name for `_zoneSecurity` Map keys: lowercase,
     * empty string for the root.
     * @param {string} zone
     * @return {string}
     * @protected
     */
    protected static _normZone(zone: string): string {
        if (zone === '.' || zone === '') {
            return '';
        }

        const stripped = zone.endsWith('.') ? zone.slice(0, -1) : zone;
        return stripped.toLowerCase();
    }

    /**
     * The chain of zones from the trust anchor down to `target`. For
     * anchor `''` (root) and target `example.com.`, returns
     * `['.', 'com', 'example.com']`. Each entry is in the canonical
     * form expected by `validateDnskeyRrset` / `validateRrset` (no
     * trailing dot, except root which is `'.'`).
     * @param {string} anchorZone
     * @param {string} target
     * @return {string[]}
     * @protected
     */
    protected static _chainPath(anchorZone: string, target: string): string[] {
        const anchorNorm = RecursiveResolver._normZone(anchorZone);
        const targetNorm = RecursiveResolver._normZone(target);

        if (targetNorm === anchorNorm) {
            return [anchorNorm === '' ? '.' : anchorNorm];
        }

        const targetLabels = targetNorm.split('.');
        const anchorLabels = anchorNorm === '' ? [] : anchorNorm.split('.');
        const relCount = targetLabels.length - anchorLabels.length;

        if (relCount <= 0) {
            return [anchorNorm === '' ? '.' : anchorNorm];
        }

        const out: string[] = [anchorNorm === '' ? '.' : anchorNorm];

        for (let i = relCount - 1; i >= 0; i--) {
            out.push(targetLabels.slice(i).join('.'));
        }

        return out;
    }

    /**
     * `child` is a strict subdomain of `parent`. The root is a strict
     * parent of any non-root name.
     * @protected
     */
    protected static _isStrictlyDeeper(child: string, parent: string): boolean {
        const childLabels = RecursiveResolver._labels(child).length;
        const parentLabels = RecursiveResolver._labels(parent).length;

        if (childLabels <= parentLabels) {
            return false;
        }

        return Bailiwick.contains(parent, child);
    }

}

/**
 * Per-resolution scratch state — internal to the resolver.
 */
type ResolveCtx = {
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
};

/**
 * Cached per-zone authentication state.
 */
type ZoneSecurity = {
    validity: DnssecValidity;
    dnskeys?: PacketResource[];
    rrsigs?: PacketResource[];
    reason?: string;
};