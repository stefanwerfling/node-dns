import dgram from 'dgram';
import tcp from 'net';
import { Bailiwick } from '../Lib/Bailiwick.js';
import { Random0x20 } from '../Lib/Random0x20.js';
import { SocketReader } from '../Lib/SocketReader.js';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { CNAME } from '../Packet/Types/CNAME.js';
import { EDNS } from '../Packet/Types/EDNS.js';
import { DNAME } from '../Packet/Types/DNAME.js';
import { NS } from '../Packet/Types/NS.js';
import { SOA } from '../Packet/Types/SOA.js';
import { DnsCache } from './DnsCache.js';
import { DnssecChain } from './DnssecChain.js';
import { NegativeProof } from './NegativeProof.js';
import { RootHints } from './RootHints.js';
import { TrustAnchors } from './TrustAnchor.js';
export const RCODE = Object.freeze({
    NOERROR: 0,
    FORMERR: 1,
    SERVFAIL: 2,
    NXDOMAIN: 3,
    NOTIMP: 4,
    REFUSED: 5
});
export class RecursiveResolver {
    _cache;
    _transport;
    _use0x20;
    _timeoutMs;
    _queryTimeoutMs;
    _maxQueries;
    _maxCnameDepth;
    _port;
    _tcpFallback;
    _tcpPort;
    _tcpTransport;
    _useEdns;
    _udpPayloadSize;
    _dnssecEnabled;
    _trustAnchors;
    _dnssecMode;
    _dnssecVerifyOptions;
    _zoneSecurity;
    constructor(options = {}) {
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
    cache() {
        return this._cache;
    }
    async resolve(qname, qtype, options = {}) {
        const qclass = options.qclass ?? PacketClass.IN;
        const ctx = {
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
        }
        catch (err) {
            return RecursiveResolver._buildResponse(ctx, RCODE.SERVFAIL, [], []);
        }
    }
    async _resolveOnce(qname, qtype, qclass, ctx) {
        const direct = this._cache.get(qname, qtype, qclass);
        if (direct !== null) {
            return RecursiveResolver._cacheEntryToResponse(ctx, direct);
        }
        if (qtype !== PacketTypes.CNAME) {
            const cnameHit = this._cache.get(qname, PacketTypes.CNAME, qclass);
            if (cnameHit !== null && cnameHit.records.length > 0) {
                return this._followCnameFromCache(qname, qtype, qclass, ctx, cnameHit.records);
            }
        }
        let currentName = qname;
        let currentType = qtype;
        let lastResponse = null;
        for (let safety = 0; safety < ctx.maxQueries; safety++) {
            this._guardBudget(ctx);
            const nsZone = this._findClosestNs(currentName, qclass);
            if (nsZone === null) {
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
            if (response.header.aa === 1 && response.answers.length > 0) {
                const handled = await this._handleAnswer(response, currentName, currentType, qclass, ctx);
                return this._dnssecFinalize(handled, response, nsZone.zone, ctx);
            }
            if (response.header.aa === 1 && response.header.rcode === RCODE.NXDOMAIN) {
                const built = RecursiveResolver._buildResponse(ctx, RCODE.NXDOMAIN, ctx.chain, RecursiveResolver._extractSoa(response));
                return this._dnssecFinalize(built, response, nsZone.zone, ctx);
            }
            if (response.header.aa === 1 && response.header.rcode === RCODE.NOERROR) {
                const built = RecursiveResolver._buildResponse(ctx, RCODE.NOERROR, ctx.chain, RecursiveResolver._extractSoa(response));
                return this._dnssecFinalize(built, response, nsZone.zone, ctx);
            }
            const referralZone = this._referralZone(response, nsZone.zone);
            if (referralZone === null) {
                continue;
            }
            if (!RecursiveResolver._isStrictlyDeeper(referralZone, nsZone.zone)) {
                throw new Error(`RecursiveResolver: non-progressing referral ${nsZone.zone} → ${referralZone}`);
            }
        }
        if (lastResponse !== null) {
            return RecursiveResolver._buildResponse(ctx, lastResponse.header.rcode, ctx.chain, []);
        }
        throw new Error('RecursiveResolver: query budget exhausted');
    }
    _findClosestNs(qname, qclass) {
        const labels = RecursiveResolver._labels(qname);
        for (let i = 0; i <= labels.length; i++) {
            const zone = labels.slice(i).join('.') || '.';
            const hit = this._cache.get(zone, PacketTypes.NS, qclass);
            if (hit !== null && hit.records.length > 0) {
                return { zone: zone, ns: hit.records.slice() };
            }
        }
        return null;
    }
    async _pickNsAddress(nsZone, qclass, ctx) {
        for (const r of nsZone.ns) {
            if (!(r.packetType instanceof NS)) {
                continue;
            }
            const a = this._cache.get(r.packetType.ns, PacketTypes.A, qclass);
            if (a !== null && a.records.length > 0) {
                return a.records[0].packetType.address;
            }
        }
        for (const r of nsZone.ns) {
            if (!(r.packetType instanceof NS)) {
                continue;
            }
            const aaaa = this._cache.get(r.packetType.ns, PacketTypes.AAAA, qclass);
            if (aaaa !== null && aaaa.records.length > 0) {
                return aaaa.records[0].packetType.address;
            }
        }
        for (const r of nsZone.ns) {
            if (!(r.packetType instanceof NS)) {
                continue;
            }
            const nsName = r.packetType.ns;
            if (Bailiwick.contains(nsZone.zone, nsName)) {
                continue;
            }
            try {
                const savedChain = ctx.chain;
                const savedDepth = ctx.cnameDepth;
                ctx.chain = [];
                ctx.cnameDepth = 0;
                try {
                    await this._resolveOnce(nsName, PacketTypes.A, qclass, ctx);
                }
                finally {
                    ctx.chain = savedChain;
                    ctx.cnameDepth = savedDepth;
                }
                const refreshed = this._cache.get(nsName, PacketTypes.A, qclass);
                if (refreshed !== null && refreshed.records.length > 0) {
                    return refreshed.records[0].packetType.address;
                }
            }
            catch {
            }
        }
        return null;
    }
    async _queryServer(serverIp, qname, qtype, qclass, ctx) {
        const sentName = this._use0x20 ? Random0x20.scramble(qname) : qname;
        const query = new Packet();
        query.header.id = (Math.random() * 0xFFFF) | 0;
        query.header.rd = 0;
        query.questions.push(new PacketQuestion(sentName, qtype, qclass));
        if (this._useEdns) {
            query.additionals.push(EDNS.createResource([], this._udpPayloadSize, this._dnssecEnabled));
        }
        const response = await this._sendAndVerify(this._transport, this._port, serverIp, query, sentName, ctx);
        if (response.header.tc === 1 && this._tcpFallback) {
            return this._sendAndVerify(this._tcpTransport, this._tcpPort, serverIp, query, sentName, ctx);
        }
        return response;
    }
    async _sendAndVerify(transport, port, serverIp, query, sentName, ctx) {
        ctx.queriesIssued++;
        this._guardBudget(ctx);
        const remaining = Math.max(1, ctx.timeoutMs - (Date.now() - ctx.startTime));
        const deadline = Math.min(ctx.queryTimeoutMs, remaining);
        const q = query.questions[0];
        const response = await RecursiveResolver._withTimeout(transport(serverIp, port, query), deadline, `query ${serverIp} for ${q.name}/${q.type}`);
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
    _cacheResponse(response, zone) {
        const filtered = Bailiwick.filter(response, zone);
        const groups = new Map();
        const all = [...filtered.answers, ...filtered.authorities, ...filtered.additionals];
        for (const r of all) {
            if (r.packetType.type === PacketTypes.EDNS) {
                continue;
            }
            const key = `${r.name.toLowerCase()}|${r.packetType.type}|${r.class}`;
            const bucket = groups.get(key);
            if (bucket === undefined) {
                groups.set(key, [r]);
            }
            else {
                bucket.push(r);
            }
        }
        for (const recs of groups.values()) {
            const ttl = RecursiveResolver._minTtl(recs);
            this._cache.set(recs[0].name, recs[0].packetType.type, recs[0].class, recs, ttl);
        }
        if (response.header.aa === 1 && response.questions.length > 0) {
            const q = response.questions[0];
            const soa = RecursiveResolver._extractSoa(response);
            if (response.header.rcode === RCODE.NXDOMAIN) {
                const ttl = RecursiveResolver._negativeTtl(soa);
                this._cache.setNegative(q.name, q.type, q.class, 'NXDOMAIN', ttl);
            }
            else if (response.header.rcode === RCODE.NOERROR && response.answers.length === 0) {
                const ttl = RecursiveResolver._negativeTtl(soa);
                this._cache.setNegative(q.name, q.type, q.class, 'NODATA', ttl);
            }
        }
    }
    async _handleAnswer(response, qname, qtype, qclass, ctx) {
        const direct = response.answers.filter((r) => RecursiveResolver._nameEquals(r.name, qname) && r.packetType.type === qtype);
        if (direct.length > 0) {
            ctx.chain.push(...direct);
            return RecursiveResolver._buildResponse(ctx, RCODE.NOERROR, ctx.chain, []);
        }
        const cname = response.answers.find((r) => RecursiveResolver._nameEquals(r.name, qname)
            && (r.packetType instanceof CNAME || r.packetType instanceof DNAME));
        if (cname !== undefined && qtype !== PacketTypes.CNAME) {
            ctx.chain.push(cname);
            ctx.cnameDepth++;
            if (ctx.cnameDepth > ctx.maxCnameDepth) {
                throw new Error(`RecursiveResolver: CNAME chain exceeded ${ctx.maxCnameDepth} hops`);
            }
            const targetName = cname.packetType instanceof CNAME
                ? cname.packetType.domain
                : cname.packetType.target;
            for (const a of response.answers) {
                if (RecursiveResolver._nameEquals(a.name, targetName) && a.packetType.type === qtype) {
                    ctx.chain.push(a);
                    return RecursiveResolver._buildResponse(ctx, RCODE.NOERROR, ctx.chain, []);
                }
            }
            return this._resolveOnce(targetName, qtype, qclass, ctx);
        }
        return RecursiveResolver._buildResponse(ctx, RCODE.NOERROR, ctx.chain, RecursiveResolver._extractSoa(response));
    }
    async _followCnameFromCache(qname, qtype, qclass, ctx, cnameRecords) {
        ctx.chain.push(...cnameRecords);
        ctx.cnameDepth++;
        if (ctx.cnameDepth > ctx.maxCnameDepth) {
            throw new Error(`RecursiveResolver: CNAME chain exceeded ${ctx.maxCnameDepth} hops`);
        }
        const target = cnameRecords[0].packetType.domain;
        return this._resolveOnce(target, qtype, qclass, ctx);
    }
    _referralZone(response, currentZone) {
        let candidate = null;
        for (const r of response.authorities) {
            if (!(r.packetType instanceof NS)) {
                continue;
            }
            if (candidate === null) {
                candidate = r.name;
            }
            else if (!RecursiveResolver._nameEquals(r.name, candidate)) {
                return null;
            }
        }
        if (candidate === null) {
            return null;
        }
        return RecursiveResolver._isStrictlyDeeper(candidate, currentZone) ? candidate : null;
    }
    _guardBudget(ctx) {
        if (Date.now() - ctx.startTime > ctx.timeoutMs) {
            throw new Error(`RecursiveResolver: total timeout (${ctx.timeoutMs}ms)`);
        }
        if (ctx.queriesIssued >= ctx.maxQueries) {
            throw new Error(`RecursiveResolver: max queries (${ctx.maxQueries})`);
        }
    }
    async _dnssecFinalize(builtResponse, rawResponse, signingZone, ctx) {
        if (!this._dnssecEnabled || ctx.inAuthChain) {
            return builtResponse;
        }
        const validity = await this._validateResponse(rawResponse, signingZone, ctx);
        if (validity === 'bogus') {
            return RecursiveResolver._buildResponse(ctx, RCODE.SERVFAIL, [], []);
        }
        if (validity === 'insecure' && this._dnssecMode === 'strict') {
            return RecursiveResolver._buildResponse(ctx, RCODE.SERVFAIL, [], []);
        }
        builtResponse.header.z = validity === 'secure'
            ? builtResponse.header.z | 0b010
            : builtResponse.header.z & ~0b010;
        return builtResponse;
    }
    async _validateResponse(response, signingZone, ctx) {
        const zoneState = await this._authenticateZone(signingZone, ctx);
        if (zoneState.validity !== 'secure') {
            return zoneState.validity;
        }
        const dnskeys = zoneState.dnskeys ?? [];
        const sections = [...response.answers, ...response.authorities];
        const groups = DnssecChain.groupRrsets(sections);
        const rrsigs = DnssecChain.rrsigs(sections);
        for (const [, recs] of groups) {
            const owner = recs[0].name;
            const matchingSigs = DnssecChain.rrsigsFor(rrsigs, owner, recs[0].packetType.type);
            if (matchingSigs.length === 0) {
                continue;
            }
            const r = DnssecChain.validateRrset(owner, recs, matchingSigs, dnskeys, this._dnssecVerifyOptions);
            if (r.validity === 'bogus') {
                return 'bogus';
            }
        }
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
            }
            else {
                const proven = (nsec.length > 0 && NegativeProof.verifyNodataNsec(qname, qtype, nsec))
                    || (nsec3.length > 0 && NegativeProof.verifyNodataNsec3(qname, qtype, signingZone, nsec3));
                if (nsec.length + nsec3.length > 0 && !proven) {
                    return 'bogus';
                }
            }
        }
        return 'secure';
    }
    async _authenticateZone(zone, ctx) {
        const norm = RecursiveResolver._normZone(zone);
        const cached = this._zoneSecurity.get(norm);
        if (cached !== undefined) {
            return cached;
        }
        const anchor = TrustAnchors.findFor(this._trustAnchors, zone);
        if (anchor === undefined) {
            const out = { validity: 'indeterminate', reason: 'no trust anchor covers zone' };
            this._zoneSecurity.set(norm, out);
            return out;
        }
        const path = RecursiveResolver._chainPath(anchor.zone, zone);
        let parentDsList = [anchor.ds];
        const subCtx = { ...ctx, inAuthChain: true };
        let result = { validity: 'indeterminate' };
        for (let i = 0; i < path.length; i++) {
            const step = path[i];
            const stepNorm = RecursiveResolver._normZone(step);
            const stepCached = this._zoneSecurity.get(stepNorm);
            if (stepCached?.validity === 'secure') {
                result = stepCached;
                if (i + 1 < path.length) {
                    const dsResult = await this._fetchAndValidateDs(path[i + 1], stepCached.dnskeys ?? [], subCtx);
                    if (dsResult.kind === 'secure') {
                        parentDsList = dsResult.ds;
                        continue;
                    }
                    if (dsResult.kind === 'insecure') {
                        const insec = { validity: 'insecure', reason: dsResult.reason };
                        this._zoneSecurity.set(RecursiveResolver._normZone(path[i + 1]), insec);
                        if (RecursiveResolver._normZone(path[i + 1]) === norm) {
                            return insec;
                        }
                        return insec;
                    }
                    const bogus = { validity: 'bogus', reason: dsResult.reason };
                    this._zoneSecurity.set(RecursiveResolver._normZone(path[i + 1]), bogus);
                    return bogus;
                }
                continue;
            }
            if (stepCached?.validity === 'bogus' || stepCached?.validity === 'insecure') {
                return stepCached;
            }
            try {
                await this._resolveOnce(step, PacketTypes.DNSKEY, PacketClass.IN, subCtx);
            }
            catch (e) {
                const bogus = { validity: 'bogus', reason: `failed to fetch DNSKEY for ${step}` };
                this._zoneSecurity.set(stepNorm, bogus);
                return bogus;
            }
            const dnskeyEntry = this._cache.get(step, PacketTypes.DNSKEY, PacketClass.IN);
            const rrsigEntry = this._cache.get(step, PacketTypes.RRSIG, PacketClass.IN);
            const dnskeys = dnskeyEntry?.records ?? [];
            const dnskeyRrsigs = DnssecChain.rrsigsFor(rrsigEntry?.records ?? [], step, PacketTypes.DNSKEY);
            const validated = DnssecChain.validateDnskeyRrset(step, dnskeys, dnskeyRrsigs, parentDsList, this._dnssecVerifyOptions);
            if (validated.validity !== 'secure') {
                const bogus = { validity: 'bogus', reason: validated.reason ?? 'DNSKEY validation failed' };
                this._zoneSecurity.set(stepNorm, bogus);
                return bogus;
            }
            const stepSec = { validity: 'secure', dnskeys: dnskeys, rrsigs: dnskeyRrsigs };
            this._zoneSecurity.set(stepNorm, stepSec);
            result = stepSec;
            if (i + 1 < path.length) {
                const dsResult = await this._fetchAndValidateDs(path[i + 1], dnskeys, subCtx);
                if (dsResult.kind === 'secure') {
                    parentDsList = dsResult.ds;
                    continue;
                }
                if (dsResult.kind === 'insecure') {
                    const insec = { validity: 'insecure', reason: dsResult.reason };
                    this._zoneSecurity.set(RecursiveResolver._normZone(path[i + 1]), insec);
                    return insec;
                }
                const bogus = { validity: 'bogus', reason: dsResult.reason };
                this._zoneSecurity.set(RecursiveResolver._normZone(path[i + 1]), bogus);
                return bogus;
            }
        }
        return result;
    }
    async _fetchAndValidateDs(zone, parentDnskeys, ctx) {
        let dsResp;
        try {
            dsResp = await this._queryDsAtParent(zone, ctx);
        }
        catch (e) {
            return { kind: 'bogus', reason: `failed to fetch DS for ${zone}` };
        }
        const dsEntry = this._cache.get(zone, PacketTypes.DS, PacketClass.IN);
        const rrsigEntry = this._cache.get(zone, PacketTypes.RRSIG, PacketClass.IN);
        const dsRecords = dsEntry?.records ?? [];
        const dsRrsigs = DnssecChain.rrsigsFor(rrsigEntry?.records ?? [], zone, PacketTypes.DS);
        if (dsRecords.length === 0) {
            if (dsResp.header.rcode !== RCODE.NOERROR) {
                return { kind: 'bogus', reason: 'DS query did not return NOERROR' };
            }
            const proven = this._verifyInsecureDelegationProof(zone, dsResp, parentDnskeys);
            if (!proven) {
                return { kind: 'bogus', reason: 'no valid NSEC/NSEC3 proof of insecure delegation' };
            }
            return { kind: 'insecure', reason: 'no DS record (insecure delegation, proved)' };
        }
        const validated = DnssecChain.validateRrset(zone, dsRecords, dsRrsigs, parentDnskeys, this._dnssecVerifyOptions);
        if (validated.validity !== 'secure') {
            return { kind: 'bogus', reason: validated.reason ?? 'DS RRset signature did not verify' };
        }
        return { kind: 'secure', ds: dsRecords.map((r) => r.packetType) };
    }
    _verifyInsecureDelegationProof(delegationName, response, parentDnskeys) {
        const auth = response.authorities;
        const nsecs = auth.filter((r) => r.packetType.type === PacketTypes.NSEC);
        const nsec3s = auth.filter((r) => r.packetType.type === PacketTypes.NSEC3);
        if (nsecs.length === 0 && nsec3s.length === 0) {
            return false;
        }
        const groups = DnssecChain.groupRrsets(auth);
        const rrsigs = DnssecChain.rrsigs(auth);
        for (const [, recs] of groups) {
            const t = recs[0].packetType.type;
            if (t !== PacketTypes.NSEC && t !== PacketTypes.NSEC3) {
                continue;
            }
            const owner = recs[0].name;
            const matchingSigs = DnssecChain.rrsigsFor(rrsigs, owner, t);
            if (matchingSigs.length === 0) {
                return false;
            }
            const v = DnssecChain.validateRrset(owner, recs, matchingSigs, parentDnskeys, this._dnssecVerifyOptions);
            if (v.validity !== 'secure') {
                return false;
            }
        }
        if (nsecs.length > 0 && NegativeProof.verifyInsecureDelegationNsec(delegationName, nsecs)) {
            return true;
        }
        return nsec3s.length > 0 && NegativeProof.verifyInsecureDelegationNsec3(delegationName, nsec3s);
    }
    async _queryDsAtParent(zone, ctx) {
        const parent = RecursiveResolver._parentOf(zone);
        const ns = this._findClosestNs(parent, PacketClass.IN);
        if (ns === null) {
            throw new Error(`RecursiveResolver: no cached NS for parent of ${zone}`);
        }
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
    static _parentOf(zone) {
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
    static _defaultUdpTransport(serverIp, port, query) {
        return new Promise((resolve, reject) => {
            const family = serverIp.includes(':') ? 'udp6' : 'udp4';
            const socket = dgram.createSocket(family);
            let settled = false;
            const finish = (err, packet) => {
                if (settled) {
                    return;
                }
                settled = true;
                try {
                    socket.close();
                }
                catch {
                }
                if (err) {
                    reject(err);
                }
                else {
                    resolve(packet);
                }
            };
            socket.once('message', (msg) => {
                try {
                    finish(null, Packet.parse(msg));
                }
                catch (err) {
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
    static _defaultTcpTransport(serverIp, port, query) {
        return new Promise((resolve, reject) => {
            const socket = tcp.createConnection({ host: serverIp, port: port });
            let settled = false;
            const finish = (err, packet) => {
                if (settled) {
                    return;
                }
                settled = true;
                try {
                    socket.destroy();
                }
                catch {
                }
                if (err) {
                    reject(err);
                }
                else {
                    resolve(packet);
                }
            };
            socket.once('connect', () => {
                const message = query.toBuffer();
                const len = Buffer.alloc(2);
                len.writeUInt16BE(message.length);
                socket.write(Buffer.concat([len, message]));
            });
            SocketReader.readStream(socket).then((data) => {
                try {
                    finish(null, Packet.parse(data));
                }
                catch (err) {
                    finish(err instanceof Error ? err : new Error(String(err)));
                }
            }, (err) => finish(err));
        });
    }
    static _withTimeout(promise, ms, label) {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                reject(new Error(`RecursiveResolver: timeout after ${ms}ms (${label})`));
            }, ms);
            promise.then((value) => {
                clearTimeout(timer);
                resolve(value);
            }, (err) => {
                clearTimeout(timer);
                reject(err);
            });
        });
    }
    static _buildResponse(ctx, rcode, answers, authorities) {
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
    static _cacheEntryToResponse(ctx, entry) {
        if (entry.rcode === 'NXDOMAIN') {
            return RecursiveResolver._buildResponse(ctx, RCODE.NXDOMAIN, ctx.chain, []);
        }
        if (entry.rcode === 'NODATA') {
            return RecursiveResolver._buildResponse(ctx, RCODE.NOERROR, ctx.chain, []);
        }
        return RecursiveResolver._buildResponse(ctx, RCODE.NOERROR, [...ctx.chain, ...entry.records], []);
    }
    static _minTtl(records) {
        let min = Infinity;
        for (const r of records) {
            if (r.ttl < min) {
                min = r.ttl;
            }
        }
        return Number.isFinite(min) ? min : 0;
    }
    static _negativeTtl(soa) {
        if (soa.length === 0) {
            return 0;
        }
        const r = soa[0];
        if (!(r.packetType instanceof SOA)) {
            return 0;
        }
        return Math.min(r.packetType.minimum, r.ttl);
    }
    static _extractSoa(packet) {
        return packet.authorities.filter((r) => r.packetType instanceof SOA);
    }
    static _labels(name) {
        if (name === '.' || name === '') {
            return [];
        }
        const stripped = name.endsWith('.') ? name.slice(0, -1) : name;
        return stripped.split('.');
    }
    static _nameEquals(a, b) {
        const norm = (n) => {
            const stripped = n.endsWith('.') && n.length > 1 ? n.slice(0, -1) : n;
            return stripped.toLowerCase();
        };
        return norm(a) === norm(b);
    }
    static _normZone(zone) {
        if (zone === '.' || zone === '') {
            return '';
        }
        const stripped = zone.endsWith('.') ? zone.slice(0, -1) : zone;
        return stripped.toLowerCase();
    }
    static _chainPath(anchorZone, target) {
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
        const out = [anchorNorm === '' ? '.' : anchorNorm];
        for (let i = relCount - 1; i >= 0; i--) {
            out.push(targetLabels.slice(i).join('.'));
        }
        return out;
    }
    static _isStrictlyDeeper(child, parent) {
        const childLabels = RecursiveResolver._labels(child).length;
        const parentLabels = RecursiveResolver._labels(parent).length;
        if (childLabels <= parentLabels) {
            return false;
        }
        return Bailiwick.contains(parent, child);
    }
}
//# sourceMappingURL=RecursiveResolver.js.map