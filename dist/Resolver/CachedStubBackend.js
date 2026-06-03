import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { DnsCache } from './DnsCache.js';
import { RCODE } from './RecursiveResolver.js';
import { extractSoa, minTtl, negativeTtl } from './utils.js';
const defaultIsCacheable = (response) => {
    const rcode = response.header.rcode;
    return rcode === RCODE.NOERROR || rcode === RCODE.NXDOMAIN;
};
export class CachedStubBackend {
    _upstream;
    _cache;
    _isCacheable;
    _refreshInFlight;
    _now;
    constructor(upstream, options = {}) {
        if (typeof upstream !== 'function') {
            throw new Error('CachedStubBackend: upstream backend is required');
        }
        this._upstream = upstream;
        this._cache = options.cache ?? new DnsCache(options.cacheOptions);
        this._isCacheable = options.isCacheable ?? defaultIsCacheable;
        this._refreshInFlight = new Set();
        this._now = options.now ?? (() => Date.now());
    }
    resolve = async (name, type, cls = PacketClass.IN) => {
        const hit = this._cache.get(name, type, cls);
        if (hit !== null) {
            if (hit.stale === true || hit.prefetch === true) {
                this._scheduleRefresh(name, type, cls);
            }
            return this._buildResponse(name, type, cls, hit);
        }
        const response = await this._upstream(name, type, cls);
        this._maybeStore(name, type, cls, response);
        return response;
    };
    get cache() {
        return this._cache;
    }
    _buildResponse(qname, qtype, qclass, entry) {
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
    static _cloneWithAdjustedTtl(r, cachedAt, now) {
        const elapsedSec = Math.floor((now - cachedAt) / 1000);
        const newTtl = Math.max(0, r.ttl - elapsedSec);
        return new PacketResource(r.name, r.packetType, r.class, newTtl);
    }
    _maybeStore(qname, qtype, qclass, response) {
        if (!this._isCacheable(response)) {
            return;
        }
        const rcode = response.header.rcode;
        if (rcode === RCODE.NXDOMAIN) {
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
            const ttl = minTtl(response.answers);
            if (ttl > 0) {
                this._cache.set(qname, qtype, qclass, response.answers, ttl);
            }
        }
    }
    _scheduleRefresh(qname, qtype, qclass) {
        const key = `${qname.toLowerCase()}|${qtype}|${qclass}`;
        if (this._refreshInFlight.has(key)) {
            return;
        }
        this._refreshInFlight.add(key);
        void this._upstream(qname, qtype, qclass).then((response) => {
            this._maybeStore(qname, qtype, qclass, response);
        }, () => {
        }).finally(() => {
            this._refreshInFlight.delete(key);
        });
    }
}
//# sourceMappingURL=CachedStubBackend.js.map