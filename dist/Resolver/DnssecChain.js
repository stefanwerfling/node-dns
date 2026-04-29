import { Dnssec } from '../Lib/Dnssec.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { DNSKEY } from '../Packet/Types/DNSKEY.js';
import { RRSIG } from '../Packet/Types/RRSIG.js';
export class DnssecChain {
    static SEP_FLAG = 0x0001;
    static ZONE_FLAG = 0x0100;
    static validateDnskeyRrset(zone, dnskeys, rrsigs, parentDs, options = {}) {
        if (dnskeys.length === 0) {
            return { validity: 'bogus', reason: 'no DNSKEY records' };
        }
        if (rrsigs.length === 0) {
            return { validity: 'bogus', reason: 'no RRSIG over DNSKEY RRset' };
        }
        if (parentDs.length === 0) {
            return { validity: 'bogus', reason: 'no parent DS' };
        }
        const candidates = [];
        for (const r of dnskeys) {
            if (!(r.packetType instanceof DNSKEY)) {
                continue;
            }
            const k = r.packetType;
            if ((k.flags & DnssecChain.SEP_FLAG) === 0) {
                continue;
            }
            for (const ds of parentDs) {
                if (Dnssec.verifyDs(zone, k, ds)) {
                    candidates.push(k);
                    break;
                }
            }
        }
        if (candidates.length === 0) {
            return { validity: 'bogus', reason: 'no DNSKEY matches any parent DS' };
        }
        for (const ksk of candidates) {
            const kskTag = Dnssec.computeKeyTag(ksk);
            for (const sigResource of rrsigs) {
                if (!(sigResource.packetType instanceof RRSIG)) {
                    continue;
                }
                const sig = sigResource.packetType;
                if (sig.sigType !== PacketTypes.DNSKEY) {
                    continue;
                }
                if (sig.keyTag !== kskTag || sig.algorithm !== ksk.algorithm) {
                    continue;
                }
                let ok;
                try {
                    ok = Dnssec.verifyRrsig(zone, dnskeys, sig, ksk, options);
                }
                catch (e) {
                    return { validity: 'bogus', reason: e instanceof Error ? e.message : String(e) };
                }
                if (ok) {
                    return { validity: 'secure', byKey: { keyTag: kskTag, algorithm: ksk.algorithm } };
                }
            }
        }
        return { validity: 'bogus', reason: 'no RRSIG over DNSKEY verified under a DS-matched KSK' };
    }
    static validateRrset(owner, rrset, rrsigs, dnskeys, options = {}) {
        if (rrset.length === 0) {
            return { validity: 'bogus', reason: 'rrset is empty' };
        }
        const rrType = rrset[0].packetType.type;
        const matchingSigs = DnssecChain.rrsigsFor(rrsigs, owner, rrType);
        if (matchingSigs.length === 0) {
            return { validity: 'insecure', reason: 'no RRSIG covers this RRset' };
        }
        const zoneKeys = DnssecChain._zoneKeys(dnskeys);
        if (zoneKeys.length === 0) {
            return { validity: 'bogus', reason: 'no DNSKEY with the ZONE flag' };
        }
        for (const sigResource of matchingSigs) {
            const sig = sigResource.packetType;
            for (const k of zoneKeys) {
                const tag = Dnssec.computeKeyTag(k);
                if (sig.keyTag !== tag || sig.algorithm !== k.algorithm) {
                    continue;
                }
                let ok;
                try {
                    ok = Dnssec.verifyRrsig(owner, rrset, sig, k, options);
                }
                catch (e) {
                    return { validity: 'bogus', reason: e instanceof Error ? e.message : String(e) };
                }
                if (ok) {
                    return { validity: 'secure', byKey: { keyTag: tag, algorithm: k.algorithm } };
                }
            }
        }
        return { validity: 'bogus', reason: 'no RRSIG verified under any zone DNSKEY' };
    }
    static rrsigsFor(rrsigs, owner, type) {
        const target = DnssecChain._normalize(owner);
        const out = [];
        for (const r of rrsigs) {
            if (!(r.packetType instanceof RRSIG)) {
                continue;
            }
            if (r.packetType.sigType !== type) {
                continue;
            }
            if (DnssecChain._normalize(r.name) !== target) {
                continue;
            }
            out.push(r);
        }
        return out;
    }
    static groupRrsets(records) {
        const out = new Map();
        for (const r of records) {
            if (r.packetType.type === PacketTypes.RRSIG || r.packetType.type === PacketTypes.EDNS) {
                continue;
            }
            const key = `${DnssecChain._normalize(r.name)}|${r.packetType.type}|${r.class}`;
            const bucket = out.get(key);
            if (bucket === undefined) {
                out.set(key, [r]);
            }
            else {
                bucket.push(r);
            }
        }
        return out;
    }
    static rrsigs(records) {
        return records.filter((r) => r.packetType.type === PacketTypes.RRSIG);
    }
    static dnskeysAt(records, zone) {
        const target = DnssecChain._normalize(zone);
        return records.filter((r) => r.packetType.type === PacketTypes.DNSKEY
            && DnssecChain._normalize(r.name) === target);
    }
    static _zoneKeys(dnskeys) {
        const out = [];
        for (const r of dnskeys) {
            if (!(r.packetType instanceof DNSKEY)) {
                continue;
            }
            if ((r.packetType.flags & DnssecChain.ZONE_FLAG) === 0) {
                continue;
            }
            out.push(r.packetType);
        }
        return out;
    }
    static _normalize(name) {
        if (name === '.' || name === '') {
            return '';
        }
        const stripped = name.endsWith('.') ? name.slice(0, -1) : name;
        return stripped.toLowerCase();
    }
}
//# sourceMappingURL=DnssecChain.js.map