import { Bailiwick } from '../Lib/Bailiwick.js';
import { SOA } from '../Packet/Types/SOA.js';
export const parentOf = (zone) => {
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
export const normZone = (zone) => {
    if (zone === '.' || zone === '') {
        return '';
    }
    const stripped = zone.endsWith('.') ? zone.slice(0, -1) : zone;
    return stripped.toLowerCase();
};
export const labels = (name) => {
    if (name === '.' || name === '') {
        return [];
    }
    const stripped = name.endsWith('.') ? name.slice(0, -1) : name;
    return stripped.split('.');
};
export const nameEquals = (a, b) => {
    const norm = (n) => {
        const stripped = n.endsWith('.') && n.length > 1 ? n.slice(0, -1) : n;
        return stripped.toLowerCase();
    };
    return norm(a) === norm(b);
};
export const chainPath = (anchorZone, target) => {
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
    const out = [anchorNorm === '' ? '.' : anchorNorm];
    for (let i = relCount - 1; i >= 0; i--) {
        out.push(targetLabels.slice(i).join('.'));
    }
    return out;
};
export const isStrictlyDeeper = (child, parent) => {
    const childLabels = labels(child).length;
    const parentLabels = labels(parent).length;
    if (childLabels <= parentLabels) {
        return false;
    }
    return Bailiwick.contains(parent, child);
};
export const minTtl = (records) => {
    let min = Infinity;
    for (const r of records) {
        if (r.ttl < min) {
            min = r.ttl;
        }
    }
    return Number.isFinite(min) ? min : 0;
};
export const negativeTtl = (soa) => {
    if (soa.length === 0) {
        return 0;
    }
    const r = soa[0];
    if (!(r.packetType instanceof SOA)) {
        return 0;
    }
    return Math.min(r.packetType.minimum, r.ttl);
};
export const extractSoa = (packet) => {
    return packet.authorities.filter((r) => r.packetType instanceof SOA);
};
export const withTimeout = (promise, ms, label) => {
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
};
//# sourceMappingURL=utils.js.map