import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { DnssecChain } from './DnssecChain.js';
import { NegativeProof } from './NegativeProof.js';
import { RCODE } from './RecursiveResolver.js';
import { TrustAnchors } from './TrustAnchor.js';
import { chainPath, isStrictlyDeeper, normZone, parentOf } from './utils.js';
export class DnssecValidator {
    _host;
    _trustAnchors;
    _trustAnchorProvider;
    _mode;
    _verifyOptions;
    _zoneSecurity;
    constructor(host, options) {
        this._host = host;
        this._trustAnchors = options.trustAnchors;
        this._trustAnchorProvider = options.trustAnchorProvider;
        this._mode = options.mode;
        this._verifyOptions = options.verifyOptions;
        this._zoneSecurity = new Map();
    }
    _anchorsFor(zone) {
        if (this._trustAnchorProvider) {
            const dynamic = this._trustAnchorProvider(zone);
            if (dynamic.length > 0) {
                return dynamic;
            }
        }
        return this._trustAnchors;
    }
    async finalize(builtResponse, rawResponse, signingZone, ctx) {
        if (ctx.inAuthChain) {
            return builtResponse;
        }
        const validity = await this._validateResponse(rawResponse, signingZone, ctx);
        if (validity === 'bogus') {
            return DnssecValidator._buildServfail(ctx);
        }
        if (validity === 'insecure' && this._mode === 'strict') {
            return DnssecValidator._buildServfail(ctx);
        }
        builtResponse.header.z = validity === 'secure'
            ? builtResponse.header.z | 0b010
            : builtResponse.header.z & ~0b010;
        if (validity === 'secure') {
            const nsecCache = this._host.nsecCache?.();
            if (nsecCache) {
                nsecCache.storeFromResponse(rawResponse, signingZone);
            }
        }
        return builtResponse;
    }
    async _validateResponse(response, signingZone, ctx) {
        const zoneState = await this._authenticateZone(signingZone, ctx);
        if (zoneState.validity !== 'secure') {
            return zoneState.validity;
        }
        const dnskeys = zoneState.dnskeys ?? [];
        const sections = [...response.answers, ...response.authorities];
        const groups = DnssecChain.groupRrsets(sections);
        const rrsigs = DnssecChain.rrsigs(sections);
        for (const [, recs] of groups) {
            const owner = recs[0].name;
            const matchingSigs = DnssecChain.rrsigsFor(rrsigs, owner, recs[0].packetType.type);
            if (matchingSigs.length === 0) {
                continue;
            }
            const r = DnssecChain.validateRrset(owner, recs, matchingSigs, dnskeys, this._verifyOptions);
            if (r.validity === 'bogus') {
                return 'bogus';
            }
        }
        if (response.header.rcode === RCODE.NXDOMAIN || (response.header.rcode === RCODE.NOERROR && response.answers.length === 0)) {
            const nsec = response.authorities.filter((r) => r.packetType.type === PacketTypes.NSEC);
            const nsec3 = response.authorities.filter((r) => r.packetType.type === PacketTypes.NSEC3);
            const qname = response.questions[0]?.name ?? ctx.originalQname;
            const qtype = response.questions[0]?.type ?? ctx.originalQtype;
            if (response.header.rcode === RCODE.NXDOMAIN) {
                const proven = (nsec.length > 0 && NegativeProof.verifyNxdomainNsec(qname, signingZone, nsec))
                    || (nsec3.length > 0 && NegativeProof.verifyNxdomainNsec3(qname, signingZone, nsec3));
                if (!proven) {
                    return 'bogus';
                }
            }
            else {
                const proven = (nsec.length > 0 && NegativeProof.verifyNodataNsec(qname, qtype, nsec))
                    || (nsec3.length > 0 && NegativeProof.verifyNodataNsec3(qname, qtype, signingZone, nsec3));
                if (nsec.length + nsec3.length > 0 && !proven) {
                    return 'bogus';
                }
            }
        }
        return 'secure';
    }
    async _authenticateZone(zone, ctx) {
        const norm = normZone(zone);
        const cached = this._zoneSecurity.get(norm);
        if (cached !== undefined) {
            return cached;
        }
        const anchors = this._anchorsFor(zone);
        const liveAnchors = TrustAnchors.findAllFor(anchors, zone);
        if (liveAnchors.length === 0) {
            const out = { validity: 'indeterminate', reason: 'no trust anchor covers zone' };
            this._zoneSecurity.set(norm, out);
            return out;
        }
        const anchor = liveAnchors[0];
        const path = chainPath(anchor.zone, zone);
        let parentDsList = liveAnchors.map((a) => a.ds);
        const subCtx = { ...ctx, inAuthChain: true };
        let result = { validity: 'indeterminate' };
        for (let i = 0; i < path.length; i++) {
            const step = path[i];
            const stepNorm = normZone(step);
            const stepCached = this._zoneSecurity.get(stepNorm);
            if (stepCached?.validity === 'secure') {
                result = stepCached;
                if (i + 1 < path.length) {
                    const dsResult = await this._fetchAndValidateDs(path[i + 1], stepCached.dnskeys ?? [], subCtx);
                    if (dsResult.kind === 'secure') {
                        parentDsList = dsResult.ds;
                        continue;
                    }
                    if (dsResult.kind === 'insecure') {
                        const insec = { validity: 'insecure', reason: dsResult.reason };
                        this._zoneSecurity.set(normZone(path[i + 1]), insec);
                        return insec;
                    }
                    const bogus = { validity: 'bogus', reason: dsResult.reason };
                    this._zoneSecurity.set(normZone(path[i + 1]), bogus);
                    return bogus;
                }
                continue;
            }
            if (stepCached?.validity === 'bogus' || stepCached?.validity === 'insecure') {
                return stepCached;
            }
            try {
                await this._host._resolveOnce(step, PacketTypes.DNSKEY, PacketClass.IN, subCtx);
            }
            catch {
                const bogus = { validity: 'bogus', reason: `failed to fetch DNSKEY for ${step}` };
                this._zoneSecurity.set(stepNorm, bogus);
                return bogus;
            }
            const dnskeyEntry = this._host.cache().get(step, PacketTypes.DNSKEY, PacketClass.IN);
            const rrsigEntry = this._host.cache().get(step, PacketTypes.RRSIG, PacketClass.IN);
            const dnskeys = dnskeyEntry?.records ?? [];
            const dnskeyRrsigs = DnssecChain.rrsigsFor(rrsigEntry?.records ?? [], step, PacketTypes.DNSKEY);
            const validated = DnssecChain.validateDnskeyRrset(step, dnskeys, dnskeyRrsigs, parentDsList, this._verifyOptions);
            if (validated.validity !== 'secure') {
                const bogus = { validity: 'bogus', reason: validated.reason ?? 'DNSKEY validation failed' };
                this._zoneSecurity.set(stepNorm, bogus);
                return bogus;
            }
            const stepSec = { validity: 'secure', dnskeys: dnskeys, rrsigs: dnskeyRrsigs };
            this._zoneSecurity.set(stepNorm, stepSec);
            result = stepSec;
            if (i + 1 < path.length) {
                const dsResult = await this._fetchAndValidateDs(path[i + 1], dnskeys, subCtx);
                if (dsResult.kind === 'secure') {
                    parentDsList = dsResult.ds;
                    continue;
                }
                if (dsResult.kind === 'insecure') {
                    const insec = { validity: 'insecure', reason: dsResult.reason };
                    this._zoneSecurity.set(normZone(path[i + 1]), insec);
                    return insec;
                }
                const bogus = { validity: 'bogus', reason: dsResult.reason };
                this._zoneSecurity.set(normZone(path[i + 1]), bogus);
                return bogus;
            }
        }
        return result;
    }
    async _fetchAndValidateDs(zone, parentDnskeys, ctx) {
        let dsResp;
        try {
            dsResp = await this._queryDsAtParent(zone, ctx);
        }
        catch {
            return { kind: 'bogus', reason: `failed to fetch DS for ${zone}` };
        }
        const dsEntry = this._host.cache().get(zone, PacketTypes.DS, PacketClass.IN);
        const rrsigEntry = this._host.cache().get(zone, PacketTypes.RRSIG, PacketClass.IN);
        const dsRecords = dsEntry?.records ?? [];
        const dsRrsigs = DnssecChain.rrsigsFor(rrsigEntry?.records ?? [], zone, PacketTypes.DS);
        if (dsRecords.length === 0) {
            if (dsResp.header.rcode !== RCODE.NOERROR) {
                return { kind: 'bogus', reason: 'DS query did not return NOERROR' };
            }
            const proven = this._verifyInsecureDelegationProof(zone, dsResp, parentDnskeys);
            if (!proven) {
                return { kind: 'bogus', reason: 'no valid NSEC/NSEC3 proof of insecure delegation' };
            }
            return { kind: 'insecure', reason: 'no DS record (insecure delegation, proved)' };
        }
        const validated = DnssecChain.validateRrset(zone, dsRecords, dsRrsigs, parentDnskeys, this._verifyOptions);
        if (validated.validity !== 'secure') {
            return { kind: 'bogus', reason: validated.reason ?? 'DS RRset signature did not verify' };
        }
        return { kind: 'secure', ds: dsRecords.map((r) => r.packetType) };
    }
    _verifyInsecureDelegationProof(delegationName, response, parentDnskeys) {
        const auth = response.authorities;
        const nsecs = auth.filter((r) => r.packetType.type === PacketTypes.NSEC);
        const nsec3s = auth.filter((r) => r.packetType.type === PacketTypes.NSEC3);
        if (nsecs.length === 0 && nsec3s.length === 0) {
            return false;
        }
        const groups = DnssecChain.groupRrsets(auth);
        const rrsigs = DnssecChain.rrsigs(auth);
        for (const [, recs] of groups) {
            const t = recs[0].packetType.type;
            if (t !== PacketTypes.NSEC && t !== PacketTypes.NSEC3) {
                continue;
            }
            const owner = recs[0].name;
            const matchingSigs = DnssecChain.rrsigsFor(rrsigs, owner, t);
            if (matchingSigs.length === 0) {
                return false;
            }
            const v = DnssecChain.validateRrset(owner, recs, matchingSigs, parentDnskeys, this._verifyOptions);
            if (v.validity !== 'secure') {
                return false;
            }
        }
        if (nsecs.length > 0 && NegativeProof.verifyInsecureDelegationNsec(delegationName, nsecs)) {
            return true;
        }
        return nsec3s.length > 0 && NegativeProof.verifyInsecureDelegationNsec3(delegationName, nsec3s);
    }
    async _queryDsAtParent(zone, ctx) {
        const parent = parentOf(zone);
        const ns = this._host._findClosestNs(parent, PacketClass.IN);
        if (ns === null) {
            throw new Error(`DnssecValidator: no cached NS for parent of ${zone}`);
        }
        const stableNs = isStrictlyDeeper(ns.zone, parent) || ns.zone === normZone(zone) || ns.zone === zone
            ? this._host._findClosestNs(parentOf(ns.zone), PacketClass.IN)
            : ns;
        if (stableNs === null) {
            throw new Error(`DnssecValidator: no usable parent NS for ${zone}`);
        }
        const addr = await this._host._pickNsAddress(stableNs, PacketClass.IN, ctx);
        if (addr === null) {
            throw new Error(`DnssecValidator: no usable address for parent NS of ${zone}`);
        }
        const response = await this._host._queryServer(addr, zone, PacketTypes.DS, PacketClass.IN, ctx);
        this._host._cacheResponse(response, stableNs.zone);
        return response;
    }
    static _buildServfail(ctx) {
        const out = new Packet();
        out.header.qr = 1;
        out.header.ra = 1;
        out.header.aa = 0;
        out.header.rcode = RCODE.SERVFAIL;
        out.questions.push(new PacketQuestion(ctx.originalQname, ctx.originalQtype, ctx.qclass));
        return out;
    }
}
//# sourceMappingURL=DnssecValidator.js.map