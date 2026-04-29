import dgram from 'dgram';
import { Bailiwick } from '../Lib/Bailiwick.js';
import { Random0x20 } from '../Lib/Random0x20.js';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { CNAME } from '../Packet/Types/CNAME.js';
import { DNAME } from '../Packet/Types/DNAME.js';
import { NS } from '../Packet/Types/NS.js';
import { SOA } from '../Packet/Types/SOA.js';
import { DnsCache } from './DnsCache.js';
import { RootHints } from './RootHints.js';
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
    constructor(options = {}) {
        this._cache = options.cache ?? new DnsCache();
        this._transport = options.transport ?? RecursiveResolver._defaultUdpTransport;
        this._use0x20 = options.use0x20 ?? true;
        this._timeoutMs = options.timeoutMs ?? 10_000;
        this._queryTimeoutMs = options.queryTimeoutMs ?? 2_000;
        this._maxQueries = options.maxQueries ?? 50;
        this._maxCnameDepth = options.maxCnameDepth ?? 16;
        this._port = options.port ?? 53;
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
                return this._handleAnswer(response, currentName, currentType, qclass, ctx);
            }
            if (response.header.aa === 1 && response.header.rcode === RCODE.NXDOMAIN) {
                return RecursiveResolver._buildResponse(ctx, RCODE.NXDOMAIN, ctx.chain, RecursiveResolver._extractSoa(response));
            }
            if (response.header.aa === 1 && response.header.rcode === RCODE.NOERROR) {
                return RecursiveResolver._buildResponse(ctx, RCODE.NOERROR, ctx.chain, RecursiveResolver._extractSoa(response));
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
        ctx.queriesIssued++;
        this._guardBudget(ctx);
        const sentName = this._use0x20 ? Random0x20.scramble(qname) : qname;
        const query = new Packet();
        query.header.id = (Math.random() * 0xFFFF) | 0;
        query.header.rd = 0;
        query.questions.push(new PacketQuestion(sentName, qtype, qclass));
        const remaining = Math.max(1, ctx.timeoutMs - (Date.now() - ctx.startTime));
        const deadline = Math.min(ctx.queryTimeoutMs, remaining);
        const response = await RecursiveResolver._withTimeout(this._transport(serverIp, this._port, query), deadline, `query ${serverIp} for ${qname}/${qtype}`);
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