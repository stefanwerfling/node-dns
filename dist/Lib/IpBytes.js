import { Buffer } from 'buffer';
export class IpBytes {
    static parseIPv4(ip) {
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
    static parseIPv6(ip) {
        let work = ip;
        let v4Suffix = null;
        const lastColon = work.lastIndexOf(':');
        if (lastColon >= 0 && work.slice(lastColon + 1).includes('.')) {
            v4Suffix = IpBytes.parseIPv4(work.slice(lastColon + 1));
            work = work.slice(0, lastColon + 1) + '0:0';
        }
        const parts = work.split('::');
        if (parts.length > 2) {
            throw new Error(`IpBytes: invalid IPv6 address "${ip}"`);
        }
        const splitGroups = (s) => {
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
    static parse(ip) {
        if (ip.includes(':')) {
            return IpBytes.parseIPv6(ip);
        }
        return IpBytes.parseIPv4(ip);
    }
}
//# sourceMappingURL=IpBytes.js.map