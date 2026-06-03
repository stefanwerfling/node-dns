import {Buffer} from 'buffer';
import {IpBytes} from './IpBytes.js';

/**
 * Decision returned by `Rrl.check` for one query:
 *   - `allow`    — within the rate budget, pass it through to the handler.
 *   - `drop`     — over the budget, do not respond at all (the typical RRL
 *                  reaction; legitimate clients retry, spoofed amplification
 *                  reflectors get nothing back).
 *   - `truncate` — over the budget, but the slip mechanism elected this
 *                  query: respond with a TC=1 (truncated) header so a
 *                  legitimate client retries over TCP, where source-address
 *                  spoofing is much harder.
 */
export type RrlDecision = 'allow' | 'drop' | 'truncate';

/**
 * Configuration for `Rrl`.
 *
 * The defaults track the typical recursive/authoritative RRL profile from
 * the BIND9 implementation: aggregate by /24 IPv4 and /56 IPv6 prefix, and
 * slip every other dropped query so well-behaved clients still get a
 * recoverable signal.
 */
export type RrlOptions = {
    /**
     * Sustained allowed responses per second per (prefix, qtype) bucket.
     * Must be > 0.
     */
    maxRate: number;

    /**
     * Burst capacity — the maximum number of tokens a bucket can accumulate
     * while idle. Defaults to `maxRate`. Higher values absorb spikes from
     * legitimate bursty clients.
     */
    capacity?: number;

    /**
     * IPv4 prefix length used to group clients into a single bucket.
     * Default 24 — matches the granularity at which most ISPs assign
     * customer subnets, and is what BIND9 RRL uses.
     */
    prefixV4Bits?: number;

    /**
     * IPv6 prefix length used to group clients into a single bucket.
     * Default 56 — matches the prefix size most ISPs delegate to homes.
     */
    prefixV6Bits?: number;

    /**
     * Slip ratio: send a truncated response on every Nth over-budget
     * query, drop the rest.
     *   - `0` → never slip, always drop.
     *   - `1` → always truncate (no silent drops).
     *   - `2` (default) → every other over-budget query is truncated.
     */
    slipRatio?: number;

    /**
     * Maximum number of in-memory buckets before FIFO eviction kicks in.
     * Default 100000 — bounds memory usage under high cardinality without
     * imposing a hard policy on operators.
     */
    maxBuckets?: number;
};

type Bucket = {
    tokens: number;
    last: number;
    drops: number;
};

/**
 * Token-bucket Response Rate Limiting (BIND9-style RRL).
 *
 * Each (prefix, qtype) pair gets its own bucket of `capacity` tokens that
 * refill at `maxRate` per second. Each `check` consumes one token; if no
 * tokens remain the query is either silently dropped or — every Nth
 * over-budget query — answered with a TC=1 truncated response so
 * legitimate clients fall back to TCP.
 *
 * RRL is only meaningful for connectionless transports where source IPs
 * can be spoofed — UDP DNS is the canonical case (RFC 5358). DoT/DoH/TCP
 * do not benefit and should not run RRL.
 *
 * @docs https://datatracker.ietf.org/doc/html/draft-vixie-isc-dns-rrl-00
 */
export class Rrl {

    public readonly maxRate: number;

    public readonly capacity: number;

    public readonly prefixV4Bits: number;

    public readonly prefixV6Bits: number;

    public readonly slipRatio: number;

    public readonly maxBuckets: number;

    /**
     * Map preserves insertion order, so iterating from the start gives the
     * oldest buckets — used to enforce `maxBuckets` via FIFO eviction.
     * @protected
     */
    protected readonly _buckets: Map<string, Bucket> = new Map();

    public constructor(options: RrlOptions) {
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

    /**
     * Decide whether a query should be served, dropped, or answered with a
     * truncation hint. Pass `now` (ms epoch) to control the clock — the
     * default is `Date.now()` and is what the server should use.
     *
     * @param {string} clientIp client source IP — IPv4 dotted quad or IPv6
     *        textual form. Anything `net.isIP` accepts works.
     * @param {number} qtype query type code — separate buckets per type
     *        prevent one noisy query type from starving others.
     * @param {[number]} now epoch milliseconds; defaults to `Date.now()`.
     * @return {RrlDecision}
     */
    public check(clientIp: string, qtype: number, now: number = Date.now()): RrlDecision {
        const key = `${this._prefixKey(clientIp)}\x00${qtype}`;
        let bucket = this._buckets.get(key);

        if (bucket === undefined) {
            bucket = {tokens: this.capacity, last: now, drops: 0};

            if (this._buckets.size >= this.maxBuckets) {
                // FIFO eviction: drop the oldest bucket so we stay capped.
                const oldest = this._buckets.keys().next().value;

                if (oldest !== undefined) {
                    this._buckets.delete(oldest);
                }
            }
        } else {
            // Refill: tokens accumulate at maxRate per second since last touch.
            const elapsedSec = Math.max(0, (now - bucket.last) / 1000);
            bucket.tokens = Math.min(this.capacity, bucket.tokens + elapsedSec * this.maxRate);
            bucket.last = now;
            // Re-insert at the end to refresh "recently used" ordering.
            this._buckets.delete(key);
        }

        let decision: RrlDecision;

        if (bucket.tokens >= 1) {
            bucket.tokens -= 1;
            bucket.drops = 0;
            decision = 'allow';
        } else {
            bucket.drops += 1;

            if (this.slipRatio > 0 && bucket.drops >= this.slipRatio) {
                bucket.drops = 0;
                decision = 'truncate';
            } else {
                decision = 'drop';
            }
        }

        this._buckets.set(key, bucket);
        return decision;
    }

    /**
     * Number of currently tracked buckets — exposed for tests and operator
     * visibility (e.g. metric publishing).
     */
    public size(): number {
        return this._buckets.size;
    }

    /**
     * Drop all bucket state. Useful for tests; in production buckets self-age
     * via the FIFO cap and refill behavior, so manual clearing is rarely
     * needed.
     */
    public reset(): void {
        this._buckets.clear();
    }

    /**
     * Compute the prefix key for a given client IP. IPv4 is masked to
     * `prefixV4Bits`, IPv6 to `prefixV6Bits`. The returned string is opaque
     * — only used for bucket keying.
     * @protected
     */
    protected _prefixKey(ip: string): string {
        if (ip.includes(':')) {
            const bytes = IpBytes.parseIPv6(ip);
            Rrl._maskInPlace(bytes, this.prefixV6Bits);
            return `6:${bytes.toString('hex')}`;
        }

        const bytes = IpBytes.parseIPv4(ip);
        Rrl._maskInPlace(bytes, this.prefixV4Bits);
        return `4:${bytes.toString('hex')}`;
    }

    /**
     * Zero out trailing bits of `buf` past the given prefix length. `buf`
     * is mutated in place.
     * @protected
     */
    protected static _maskInPlace(buf: Buffer, prefixBits: number): void {
        const fullBytes = Math.floor(prefixBits / 8);
        const remBits = prefixBits % 8;

        for (let i = fullBytes; i < buf.length; i++) {
            if (i === fullBytes && remBits > 0) {
                // eslint-disable-next-line no-bitwise
                buf[i] &= (0xFF << (8 - remBits)) & 0xFF;
            } else {
                buf[i] = 0;
            }
        }
    }

}