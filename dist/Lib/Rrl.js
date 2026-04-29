import { Buffer } from 'buffer';
export class Rrl {
    maxRate;
    capacity;
    prefixV4Bits;
    prefixV6Bits;
    slipRatio;
    maxBuckets;
    _buckets = new Map();
    constructor(options) {
        if (!(options.maxRate > 0)) {
            throw new Error('Rrl: maxRate must be > 0');
        }
        this.maxRate = options.maxRate;
        this.capacity = options.capacity ?? options.maxRate;
        this.prefixV4Bits = options.prefixV4Bits ?? 24;
        this.prefixV6Bits = options.prefixV6Bits ?? 56;
        this.slipRatio = options.slipRatio ?? 2;
        this.maxBuckets = options.maxBuckets ?? 100000;
        if (this.prefixV4Bits < 0 || this.prefixV4Bits > 32) {
            throw new Error('Rrl: prefixV4Bits must be in [0, 32]');
        }
        if (this.prefixV6Bits < 0 || this.prefixV6Bits > 128) {
            throw new Error('Rrl: prefixV6Bits must be in [0, 128]');
        }
        if (this.slipRatio < 0 || !Number.isInteger(this.slipRatio)) {
            throw new Error('Rrl: slipRatio must be a non-negative integer');
        }
    }
    check(clientIp, qtype, now = Date.now()) {
        const key = `${this._prefixKey(clientIp)}\x00${qtype}`;
        let bucket = this._buckets.get(key);
        if (bucket === undefined) {
            bucket = { tokens: this.capacity, last: now, drops: 0 };
            if (this._buckets.size >= this.maxBuckets) {
                const oldest = this._buckets.keys().next().value;
                if (oldest !== undefined) {
                    this._buckets.delete(oldest);
                }
            }
        }
        else {
            const elapsedSec = Math.max(0, (now - bucket.last) / 1000);
            bucket.tokens = Math.min(this.capacity, bucket.tokens + elapsedSec * this.maxRate);
            bucket.last = now;
            this._buckets.delete(key);
        }
        let decision;
        if (bucket.tokens >= 1) {
            bucket.tokens -= 1;
            bucket.drops = 0;
            decision = 'allow';
        }
        else {
            bucket.drops += 1;
            if (this.slipRatio > 0 && bucket.drops >= this.slipRatio) {
                bucket.drops = 0;
                decision = 'truncate';
            }
            else {
                decision = 'drop';
            }
        }
        this._buckets.set(key, bucket);
        return decision;
    }
    size() {
        return this._buckets.size;
    }
    reset() {
        this._buckets.clear();
    }
    _prefixKey(ip) {
        if (ip.includes(':')) {
            const bytes = Rrl._parseIPv6(ip);
            Rrl._maskInPlace(bytes, this.prefixV6Bits);
            return `6:${bytes.toString('hex')}`;
        }
        const bytes = Rrl._parseIPv4(ip);
        Rrl._maskInPlace(bytes, this.prefixV4Bits);
        return `4:${bytes.toString('hex')}`;
    }
    static _maskInPlace(buf, prefixBits) {
        const fullBytes = Math.floor(prefixBits / 8);
        const remBits = prefixBits % 8;
        for (let i = fullBytes; i < buf.length; i++) {
            if (i === fullBytes && remBits > 0) {
                buf[i] &= (0xFF << (8 - remBits)) & 0xFF;
            }
            else {
                buf[i] = 0;
            }
        }
    }
    static _parseIPv4(ip) {
        const parts = ip.split('.');
        if (parts.length !== 4) {
            throw new Error(`Rrl: invalid IPv4 address "${ip}"`);
        }
        const out = Buffer.alloc(4);
        for (let i = 0; i < 4; i++) {
            const n = parseInt(parts[i], 10);
            if (!Number.isInteger(n) || n < 0 || n > 255 || !/^\d+$/u.test(parts[i])) {
                throw new Error(`Rrl: invalid IPv4 address "${ip}"`);
            }
            out[i] = n;
        }
        return out;
    }
    static _parseIPv6(ip) {
        let work = ip;
        let v4Suffix = null;
        const lastColon = work.lastIndexOf(':');
        if (lastColon >= 0 && work.slice(lastColon + 1).includes('.')) {
            v4Suffix = Rrl._parseIPv4(work.slice(lastColon + 1));
            work = work.slice(0, lastColon + 1) + '0:0';
        }
        const parts = work.split('::');
        if (parts.length > 2) {
            throw new Error(`Rrl: invalid IPv6 address "${ip}"`);
        }
        const splitGroups = (s) => {
            if (s.length === 0) {
                return [];
            }
            return s.split(':').map((g) => {
                if (!/^[0-9a-fA-F]{1,4}$/u.test(g)) {
                    throw new Error(`Rrl: invalid IPv6 address "${ip}"`);
                }
                return parseInt(g, 16);
            });
        };
        const head = splitGroups(parts[0]);
        const tail = parts.length === 2 ? splitGroups(parts[1]) : [];
        const total = head.length + tail.length;
        if (parts.length === 1 ? total !== 8 : total > 8) {
            throw new Error(`Rrl: invalid IPv6 address "${ip}"`);
        }
        const padding = parts.length === 2 ? new Array(8 - total).fill(0) : [];
        const groups = [...head, ...padding, ...tail];
        const out = Buffer.alloc(16);
        for (let i = 0; i < 8; i++) {
            out.writeUInt16BE(groups[i], i * 2);
        }
        if (v4Suffix !== null) {
            v4Suffix.copy(out, 12);
        }
        return out;
    }
}
//# sourceMappingURL=Rrl.js.map