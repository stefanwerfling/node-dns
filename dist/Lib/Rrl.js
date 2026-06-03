import { IpBytes } from './IpBytes.js';
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
            const bytes = IpBytes.parseIPv6(ip);
            Rrl._maskInPlace(bytes, this.prefixV6Bits);
            return `6:${bytes.toString('hex')}`;
        }
        const bytes = IpBytes.parseIPv4(ip);
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
}
//# sourceMappingURL=Rrl.js.map