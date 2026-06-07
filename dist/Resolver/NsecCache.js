import { Buffer } from 'buffer';
import { Dnssec } from '../Lib/Dnssec.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { NSEC } from '../Packet/Types/NSEC.js';
import { NSEC3 } from '../Packet/Types/NSEC3.js';
export class NsecCache {
    _nsecByZone = new Map();
    _nsec3ByZone = new Map();
    _nsec3Params = new Map();
    _now;
    _maxEntries;
    _totalNsec = 0;
    _totalNsec3 = 0;
    _insertionOrder = [];
    constructor(options = {}) {
        this._now = options.now ?? (() => Date.now());
        this._maxEntries = options.maxEntries ?? 5000;
    }
    forgetZone(zone) {
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
    clear() {
        this._nsecByZone.clear();
        this._nsec3ByZone.clear();
        this._nsec3Params.clear();
        this._insertionOrder = [];
        this._totalNsec = 0;
        this._totalNsec3 = 0;
    }
    size() {
        return this._totalNsec + this._totalNsec3;
    }
    storeFromResponse(packet, zone) {
        for (const r of packet.answers) {
            this._storeRecord(r.name, r.ttl, r.packetType, zone);
        }
        for (const r of packet.authorities) {
            this._storeRecord(r.name, r.ttl, r.packetType, zone);
        }
    }
    proveNegative(qname, qtype) {
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
        return null;
    }
    setNsec3Params(zone, params) {
        this._nsec3Params.set(NsecCache._zoneKey(zone), params);
    }
    getNsec3Params(zone) {
        return this._nsec3Params.get(NsecCache._zoneKey(zone)) ?? null;
    }
    static _zoneKey(zone) {
        return zone.toLowerCase().replace(/\.$/u, '');
    }
    static _nameKey(name) {
        return name.toLowerCase().replace(/\.$/u, '');
    }
    _storeRecord(owner, ttl, packetType, zone) {
        const now = this._now();
        if (packetType instanceof NSEC) {
            const entry = {
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
                this._insertionOrder.push({ zone: key, kind: 'nsec', idx: bucket.length - 1 });
            }
            else {
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
            const entry = {
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
                this._insertionOrder.push({ zone: key, kind: 'nsec3', idx: bucket.length - 1 });
            }
            else {
                bucket[replaceIdx] = entry;
            }
            this._nsec3ByZone.set(key, bucket);
            this._nsec3Params.set(key, {
                salt: packetType.salt,
                iterations: packetType.iterations
            });
            this._evictIfNeeded();
        }
    }
    _evictIfNeeded() {
        if (this._maxEntries === 0) {
            return;
        }
        while (this._totalNsec + this._totalNsec3 > this._maxEntries && this._insertionOrder.length > 0) {
            const oldest = this._insertionOrder.shift();
            const bucket = oldest.kind === 'nsec'
                ? this._nsecByZone.get(oldest.zone)
                : this._nsec3ByZone.get(oldest.zone);
            if (bucket && bucket.length > 0) {
                bucket.shift();
                if (oldest.kind === 'nsec') {
                    this._totalNsec--;
                }
                else {
                    this._totalNsec3--;
                }
            }
        }
    }
    _proveNodataViaNsec(qname, qtype) {
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
                if (entry.types.has(PacketTypes.CNAME)) {
                    return null;
                }
                return { kind: 'nodata', ttl: NsecCache._remainingSeconds(entry.expiresAt, now) };
            }
        }
        return null;
    }
    _proveNxdomainViaNsec(qname) {
        const qkey = NsecCache._nameKey(qname);
        const now = this._now();
        for (const [zoneKey, bucket] of this._nsecByZone) {
            const cover = bucket.find((e) => e.expiresAt > now &&
                Dnssec.nsecCovers(e.owner, e.nextDomain, qkey));
            if (!cover) {
                continue;
            }
            const closestEncloser = NsecCache._closestEncloser(qkey, cover.owner, cover.nextDomain, zoneKey);
            if (closestEncloser === null) {
                continue;
            }
            const wildcard = `*.${closestEncloser}`;
            const wildcardCover = bucket.find((e) => e.expiresAt > now &&
                (e.owner === wildcard || Dnssec.nsecCovers(e.owner, e.nextDomain, wildcard)));
            if (!wildcardCover) {
                continue;
            }
            if (wildcardCover.owner === wildcard) {
                continue;
            }
            const minRemaining = Math.min(NsecCache._remainingSeconds(cover.expiresAt, now), NsecCache._remainingSeconds(wildcardCover.expiresAt, now));
            return { kind: 'nxdomain', ttl: minRemaining };
        }
        return null;
    }
    _proveNodataViaNsec3(qname, qtype) {
        const qkey = NsecCache._nameKey(qname);
        const now = this._now();
        for (const [zoneKey, bucket] of this._nsec3ByZone) {
            const params = this._nsec3Params.get(zoneKey);
            if (!params) {
                continue;
            }
            let qhash;
            try {
                qhash = Dnssec.nsec3Hash(qkey, params.salt, params.iterations);
            }
            catch {
                continue;
            }
            const match = bucket.find((e) => e.expiresAt > now &&
                Buffer.compare(e.ownerHash, qhash) === 0);
            if (!match) {
                continue;
            }
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
            return { kind: 'nodata', ttl: NsecCache._remainingSeconds(match.expiresAt, now) };
        }
        return null;
    }
    static _closestEncloser(qname, owner, next, zone) {
        const qLabels = qname.split('.').filter((l) => l.length > 0);
        const oLabels = owner.split('.').filter((l) => l.length > 0);
        const nLabels = next.split('.').filter((l) => l.length > 0);
        const commonSuffix = (a, b) => {
            const out = [];
            for (let i = 0; i < Math.min(a.length, b.length); i++) {
                const la = a[a.length - 1 - i];
                const lb = b[b.length - 1 - i];
                if (la === lb) {
                    out.unshift(la);
                }
                else {
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
        if (closest.length > ownerNext.length) {
            closest = ownerNext;
        }
        if (closest.length === 0) {
            return null;
        }
        const candidate = closest.join('.');
        if (zone.length > 0 && !candidate.endsWith(zone)) {
            return null;
        }
        return candidate;
    }
    static _decodeBase32Hex(input) {
        const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
        const upper = input.toUpperCase();
        const bytes = [];
        let value = 0;
        let bits = 0;
        for (const ch of upper) {
            const v = alphabet.indexOf(ch);
            if (v === -1) {
                return null;
            }
            value = (value << 5) | v;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                bytes.push((value >>> bits) & 0xFF);
            }
        }
        return Buffer.from(bytes);
    }
    static _remainingSeconds(expiresAt, now) {
        return Math.max(0, Math.floor((expiresAt - now) / 1000));
    }
}
//# sourceMappingURL=NsecCache.js.map