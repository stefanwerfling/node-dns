import {Bailiwick} from '../Lib/Bailiwick.js';
import {Packet} from '../Packet/Packet.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {SOA} from '../Packet/Types/SOA.js';

/**
 * Pure name/zone manipulation and small RRset helpers extracted from
 * `RecursiveResolver`. None of these functions touch resolver state or
 * the network — they're useful in isolation for callers that build on
 * the resolver primitives (e.g. tests, application-side caching).
 */

/**
 * The parent zone of `zone` — strip the leftmost label. The parent of
 * the root is the root itself (no further to ascend).
 *
 * @param {string} zone
 * @return {string}
 */
export const parentOf = (zone: string): string => {
    const norm = normZone(zone);

    if (norm === '') {
        return '.';
    }

    const dot = norm.indexOf('.');

    if (dot === -1) {
        return '.';
    }

    return norm.slice(dot + 1);
};

/**
 * Normalize a zone name for Map keys: lowercase, no trailing dot,
 * empty string for the root.
 *
 * @param {string} zone
 * @return {string}
 */
export const normZone = (zone: string): string => {
    if (zone === '.' || zone === '') {
        return '';
    }

    const stripped = zone.endsWith('.') ? zone.slice(0, -1) : zone;
    return stripped.toLowerCase();
};

/**
 * Split a name into labels. Trailing dot is dropped.
 *
 * @param {string} name
 * @return {string[]}
 */
export const labels = (name: string): string[] => {
    if (name === '.' || name === '') {
        return [];
    }

    const stripped = name.endsWith('.') ? name.slice(0, -1) : name;
    return stripped.split('.');
};

/**
 * Case-insensitive name compare with trailing-dot tolerance.
 *
 * @param {string} a
 * @param {string} b
 * @return {boolean}
 */
export const nameEquals = (a: string, b: string): boolean => {
    const norm = (n: string): string => {
        const stripped = n.endsWith('.') && n.length > 1 ? n.slice(0, -1) : n;
        return stripped.toLowerCase();
    };

    return norm(a) === norm(b);
};

/**
 * The chain of zones from the trust anchor down to `target`. For
 * anchor `''` (root) and target `example.com.`, returns
 * `['.', 'com', 'example.com']`. Each entry is in the canonical form
 * the validator expects (no trailing dot, except root which is `'.'`).
 *
 * @param {string} anchorZone
 * @param {string} target
 * @return {string[]}
 */
export const chainPath = (anchorZone: string, target: string): string[] => {
    const anchorNorm = normZone(anchorZone);
    const targetNorm = normZone(target);

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
};

/**
 * `child` is a strict subdomain of `parent`. The root is a strict
 * parent of any non-root name.
 *
 * @param {string} child
 * @param {string} parent
 * @return {boolean}
 */
export const isStrictlyDeeper = (child: string, parent: string): boolean => {
    const childLabels = labels(child).length;
    const parentLabels = labels(parent).length;

    if (childLabels <= parentLabels) {
        return false;
    }

    return Bailiwick.contains(parent, child);
};

/**
 * RFC 1035 §3.7 — TTL of an RRset is the minimum of its records' TTLs.
 * Implementations sometimes cheat and use the max; the conservative
 * choice is min.
 *
 * @param {PacketResource[]} records
 * @return {number}
 */
export const minTtl = (records: PacketResource[]): number => {
    let min = Infinity;

    for (const r of records) {
        if (r.ttl < min) {
            min = r.ttl;
        }
    }

    return Number.isFinite(min) ? min : 0;
};

/**
 * RFC 2308 §5 — a negative answer's TTL is the SOA MINIMUM (or the
 * SOA's own TTL, whichever is smaller). Defaults to 0 when no SOA is
 * supplied (the entry won't be cached effectively).
 *
 * @param {PacketResource[]} soa
 * @return {number}
 */
export const negativeTtl = (soa: PacketResource[]): number => {
    if (soa.length === 0) {
        return 0;
    }

    const r = soa[0];

    if (!(r.packetType instanceof SOA)) {
        return 0;
    }

    return Math.min(r.packetType.minimum, r.ttl);
};

/**
 * Extract SOA records from an authority section, if any.
 *
 * @param {Packet} packet
 * @return {PacketResource[]}
 */
export const extractSoa = (packet: Packet): PacketResource[] => {
    return packet.authorities.filter((r) => r.packetType instanceof SOA);
};

/**
 * Race a promise against a timeout — used to cap individual query
 * waits.
 *
 * @param {Promise<T>} promise
 * @param {number} ms
 * @param {string} label
 * @return {Promise<T>}
 */
export const withTimeout = <T>(promise: Promise<T>, ms: number, label: string): Promise<T> => {
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
};