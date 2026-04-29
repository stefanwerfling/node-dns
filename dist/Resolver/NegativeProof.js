import { Buffer } from 'buffer';
import { Dnssec } from '../Lib/Dnssec.js';
import { NSEC } from '../Packet/Types/NSEC.js';
import { NSEC3 } from '../Packet/Types/NSEC3.js';
export class NegativeProof {
    static verifyNxdomainNsec(qname, zone, records) {
        const nsecs = NegativeProof._nsecsOnly(records);
        if (nsecs.length === 0) {
            return false;
        }
        for (const r of nsecs) {
            if (NegativeProof._nameEquals(r.name, qname)) {
                return false;
            }
        }
        const coversQ = nsecs.some((r) => Dnssec.nsecCovers(r.name, r.packetType.nextDomain, qname));
        if (!coversQ) {
            return false;
        }
        const ce = NegativeProof.closestEncloserNsec(qname, zone, nsecs);
        if (ce === null) {
            return false;
        }
        const wildcard = ce === '' || ce === '.' ? '*.' : `*.${ce}`;
        const coversW = nsecs.some((r) => Dnssec.nsecCovers(r.name, r.packetType.nextDomain, wildcard));
        return coversW;
    }
    static verifyNodataNsec(qname, qtype, records) {
        const nsecs = NegativeProof._nsecsOnly(records);
        for (const r of nsecs) {
            if (!NegativeProof._nameEquals(r.name, qname)) {
                continue;
            }
            const types = r.packetType.rdtypes;
            if (!types.includes(qtype)) {
                return true;
            }
        }
        return false;
    }
    static closestEncloserNsec(qname, zone, nsecs) {
        const owners = new Set();
        for (const r of nsecs) {
            if (r.packetType instanceof NSEC) {
                owners.add(NegativeProof._normalize(r.name));
            }
        }
        owners.add(NegativeProof._normalize(zone));
        let candidate = NegativeProof._stripFirstLabel(NegativeProof._normalize(qname));
        while (true) {
            if (owners.has(candidate)) {
                return candidate;
            }
            if (candidate === '') {
                break;
            }
            candidate = NegativeProof._stripFirstLabel(candidate);
        }
        return null;
    }
    static verifyNxdomainNsec3(qname, zone, records) {
        const nsec3s = NegativeProof._nsec3sOnly(records);
        if (nsec3s.length === 0) {
            return false;
        }
        const params = NegativeProof._nsec3Params(nsec3s);
        if (params === null) {
            return false;
        }
        const labels = NegativeProof._labels(NegativeProof._normalize(qname));
        const zoneNorm = NegativeProof._normalize(zone);
        for (let depth = 1; depth <= labels.length; depth++) {
            const candidate = labels.slice(depth).join('.');
            if (candidate.length > 0 && !NegativeProof._isAncestorOf(candidate, zoneNorm) && candidate !== zoneNorm) {
                continue;
            }
            const ceHash = Dnssec.nsec3Hash(candidate.length === 0 ? '.' : candidate, params.saltHex, params.iterations);
            const ceMatch = NegativeProof._anyNsec3Matches(nsec3s, ceHash);
            if (!ceMatch) {
                continue;
            }
            const nextCloser = labels.slice(depth - 1).join('.');
            const ncHash = Dnssec.nsec3Hash(nextCloser, params.saltHex, params.iterations);
            const ncCover = NegativeProof._anyNsec3Covers(nsec3s, ncHash);
            if (!ncCover) {
                continue;
            }
            const wildcardName = candidate.length === 0 ? '*' : `*.${candidate}`;
            const wcHash = Dnssec.nsec3Hash(wildcardName, params.saltHex, params.iterations);
            const wcCover = NegativeProof._anyNsec3Covers(nsec3s, wcHash);
            if (wcCover) {
                return true;
            }
        }
        return false;
    }
    static verifyNodataNsec3(qname, qtype, zone, records) {
        const nsec3s = NegativeProof._nsec3sOnly(records);
        if (nsec3s.length === 0) {
            return false;
        }
        const params = NegativeProof._nsec3Params(nsec3s);
        if (params === null) {
            return false;
        }
        const target = Dnssec.nsec3Hash(qname, params.saltHex, params.iterations);
        for (const r of nsec3s) {
            const ownerHash = NegativeProof._extractNsec3OwnerHash(r.name);
            if (ownerHash === null || !ownerHash.equals(target)) {
                continue;
            }
            const types = r.packetType.rdtypes;
            if (!types.includes(qtype)) {
                return true;
            }
        }
        return false;
    }
    static _nsecsOnly(records) {
        return records.filter((r) => r.packetType instanceof NSEC);
    }
    static _nsec3sOnly(records) {
        return records.filter((r) => r.packetType instanceof NSEC3);
    }
    static _nsec3Params(nsec3s) {
        if (nsec3s.length === 0) {
            return null;
        }
        const first = nsec3s[0].packetType;
        return { saltHex: first.salt, iterations: first.iterations };
    }
    static _anyNsec3Matches(nsec3s, target) {
        for (const r of nsec3s) {
            const ownerHash = NegativeProof._extractNsec3OwnerHash(r.name);
            if (ownerHash !== null && ownerHash.equals(target)) {
                return true;
            }
        }
        return false;
    }
    static _anyNsec3Covers(nsec3s, target) {
        for (const r of nsec3s) {
            const ownerHash = NegativeProof._extractNsec3OwnerHash(r.name);
            if (ownerHash === null) {
                continue;
            }
            const nextHash = NegativeProof._decodeNsec3NextHash(r.packetType.nextHashedOwner);
            if (nextHash === null) {
                continue;
            }
            if (Dnssec.nsec3CoversHash(ownerHash, nextHash, target)) {
                return true;
            }
        }
        return false;
    }
    static _decodeNsec3NextHash(encoded) {
        try {
            return NegativeProof._base32hexDecode(encoded.toUpperCase());
        }
        catch {
            return null;
        }
    }
    static _extractNsec3OwnerHash(ownerName) {
        const dot = ownerName.indexOf('.');
        const label = dot === -1 ? ownerName : ownerName.slice(0, dot);
        try {
            return NegativeProof._base32hexDecode(label.toUpperCase());
        }
        catch {
            return null;
        }
    }
    static _base32hexDecode(s) {
        const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
        const padding = s.replace(/=+$/u, '');
        const bytes = [];
        let buffer = 0;
        let bits = 0;
        for (const ch of padding) {
            const v = alphabet.indexOf(ch);
            if (v === -1) {
                throw new Error(`base32hex: invalid character ${ch}`);
            }
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                bytes.push((buffer >> bits) & 0xFF);
            }
        }
        return Buffer.from(bytes);
    }
    static _stripFirstLabel(name) {
        const dot = name.indexOf('.');
        return dot === -1 ? '' : name.slice(dot + 1);
    }
    static _labels(name) {
        if (name === '') {
            return [];
        }
        return name.split('.');
    }
    static _isAncestorOf(child, parent) {
        if (parent === '') {
            return true;
        }
        return child === parent || child.endsWith(`.${parent}`);
    }
    static _nameEquals(a, b) {
        return NegativeProof._normalize(a) === NegativeProof._normalize(b);
    }
    static _normalize(name) {
        if (name === '.' || name === '') {
            return '';
        }
        const stripped = name.endsWith('.') ? name.slice(0, -1) : name;
        return stripped.toLowerCase();
    }
}
//# sourceMappingURL=NegativeProof.js.map