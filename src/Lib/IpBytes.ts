import {Buffer} from 'buffer';

/**
 * Textual-form IP address → raw bytes.
 *
 * IPv4 → 4 bytes, IPv6 → 16 bytes. Handles RFC 4291 `::`
 * zero-compression and the IPv4-tail form `::ffff:1.2.3.4`. Used by
 * any code that needs a canonical wire-form of a client address —
 * RFC 5358 RRL keying, RFC 7873 EDNS cookie HMAC input, etc.
 *
 * Strict parsers — throw on malformed input rather than returning
 * `null` so callers can't accidentally use a degenerate value. Callers
 * that need fall-back behaviour should wrap in try/catch.
 */
export class IpBytes {

    /**
     * Parse an IPv4 dotted-quad into 4 bytes. Throws on malformed input.
     *
     * @param {string} ip
     * @return {Buffer}
     */
    public static parseIPv4(ip: string): Buffer {
        const parts = ip.split('.');

        if (parts.length !== 4) {
            throw new Error(`IpBytes: invalid IPv4 address "${ip}"`);
        }

        const out = Buffer.alloc(4);

        for (let i = 0; i < 4; i++) {
            const n = parseInt(parts[i], 10);

            if (!Number.isInteger(n) || n < 0 || n > 255 || !/^\d+$/u.test(parts[i])) {
                throw new Error(`IpBytes: invalid IPv4 address "${ip}"`);
            }

            out[i] = n;
        }

        return out;
    }

    /**
     * Parse an IPv6 address (RFC 4291 textual form, including `::`
     * zero-compression and the IPv4-tail form `::ffff:1.2.3.4`) into
     * 16 bytes. Throws on malformed input.
     *
     * @param {string} ip
     * @return {Buffer}
     */
    public static parseIPv6(ip: string): Buffer {
        let work = ip;
        let v4Suffix: Buffer|null = null;

        const lastColon = work.lastIndexOf(':');

        if (lastColon >= 0 && work.slice(lastColon + 1).includes('.')) {
            v4Suffix = IpBytes.parseIPv4(work.slice(lastColon + 1));
            work = work.slice(0, lastColon + 1) + '0:0';
        }

        const parts = work.split('::');

        if (parts.length > 2) {
            throw new Error(`IpBytes: invalid IPv6 address "${ip}"`);
        }

        const splitGroups = (s: string): number[] => {
            if (s.length === 0) {
                return [];
            }

            return s.split(':').map((g) => {
                if (!/^[0-9a-fA-F]{1,4}$/u.test(g)) {
                    throw new Error(`IpBytes: invalid IPv6 address "${ip}"`);
                }

                return parseInt(g, 16);
            });
        };

        const head = splitGroups(parts[0]);
        const tail = parts.length === 2 ? splitGroups(parts[1]) : [];
        const total = head.length + tail.length;

        if (parts.length === 1 ? total !== 8 : total > 8) {
            throw new Error(`IpBytes: invalid IPv6 address "${ip}"`);
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

    /**
     * Auto-detect IPv4 vs IPv6 from `ip` (presence of `:` flips to v6)
     * and dispatch. Returns the parsed bytes (4 or 16). Throws when
     * the address is neither valid IPv4 nor IPv6.
     *
     * @param {string} ip
     * @return {Buffer}
     */
    public static parse(ip: string): Buffer {
        if (ip.includes(':')) {
            return IpBytes.parseIPv6(ip);
        }

        return IpBytes.parseIPv4(ip);
    }

}