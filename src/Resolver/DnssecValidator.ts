import {DnssecVerifyOptions} from '../Lib/Dnssec.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {DS} from '../Packet/Types/DS.js';
import {DnsCache} from './DnsCache.js';
import {DnssecChain, DnssecValidity} from './DnssecChain.js';
import {NegativeProof} from './NegativeProof.js';
import {RCODE} from './RecursiveResolver.js';
import type {ResolveCtx} from './RecursiveResolver.js';
import {TrustAnchor, TrustAnchors} from './TrustAnchor.js';
import {chainPath, isStrictlyDeeper, normZone, parentOf} from './utils.js';

/**
 * Failure policy.
 *
 * - `permissive` accepts insecure zones (no DS at parent proven via
 *   NSEC/NSEC3) and only fails closed on `bogus`.
 * - `strict` also rejects answers whose chain cannot be authenticated
 *   end-to-end — appropriate when the deployment policy requires every
 *   secure answer be DNSSEC-validated.
 */
export type DnssecMode = 'strict' | 'permissive';

/**
 * Per-validator configuration.
 */
export type DnssecValidatorOptions = {
    /** Trust anchors covering the answer's signing zone. */
    trustAnchors: ReadonlyArray<TrustAnchor>;

    /** Failure policy. */
    mode: DnssecMode;

    /** Forwarded to `Dnssec.verifyRrsig` — fixed clock for tests. */
    verifyOptions: DnssecVerifyOptions;
};

/**
 * Narrow contract that the validator needs from its host resolver.
 * `RecursiveResolver` implements it directly via `@internal`-marked
 * public methods. The interface keeps the validator decoupled from
 * the resolver's internal layout — any other engine that drives the
 * iterative loop can wire DNSSEC in by satisfying it.
 *
 * @internal
 */
export interface DnssecResolverHost {
    cache(): DnsCache;

    /** @internal */
    _resolveOnce(qname: string, qtype: number | PacketTypes, qclass: PacketClass, ctx: ResolveCtx): Promise<Packet>;

    /** @internal */
    _queryServer(serverIp: string, qname: string, qtype: number | PacketTypes, qclass: PacketClass, ctx: ResolveCtx): Promise<Packet>;

    /** @internal */
    _findClosestNs(qname: string, qclass: PacketClass): {zone: string; ns: PacketResource[];} | null;

    /** @internal */
    _pickNsAddress(nsZone: {zone: string; ns: PacketResource[];}, qclass: PacketClass, ctx: ResolveCtx): Promise<string | null>;

    /** @internal */
    _cacheResponse(response: Packet, zone: string): void;
}

/**
 * Cached per-zone authentication state.
 */
type ZoneSecurity = {
    validity: DnssecValidity;
    dnskeys?: PacketResource[];
    rrsigs?: PacketResource[];
    reason?: string;
};

/**
 * DNSSEC validator (RFC 4034 / 4035 / 5155). Walks the chain top-down
 * from a configured trust anchor down to the answer's signing zone,
 * validates DNSKEY-against-DS at every step, then validates each
 * signed RRset (and any negative-answer NSEC/NSEC3 proofs) against
 * the authenticated DNSKEY set.
 *
 * Composition: the validator is a separate concern that
 * `RecursiveResolver` plugs in when its `dnssec` option is set. DNSSEC
 * is integral to a real-world recursor (BIND/Unbound/Knot validate by
 * default) but the validator is still a separate object — easier to
 * reason about, easier to swap out for forwarding setups that delegate
 * validation to the upstream.
 *
 * The validator drives DNSKEY/DS sub-resolutions through the host
 * resolver's iterative loop, flagged with `ctx.inAuthChain: true` so
 * those sub-queries don't themselves get re-validated (would recurse
 * forever). The host's `_dnssecFinalize` short-circuit honours the
 * flag.
 */
export class DnssecValidator {

    /**
     * @protected
     */
    protected _host: DnssecResolverHost;

    /**
     * @protected
     */
    protected _trustAnchors: ReadonlyArray<TrustAnchor>;

    /**
     * @protected
     */
    protected _mode: DnssecMode;

    /**
     * @protected
     */
    protected _verifyOptions: DnssecVerifyOptions;

    /**
     * Per-zone authentication state cache.
     * @protected
     */
    protected _zoneSecurity: Map<string, ZoneSecurity>;

    /**
     * @param {DnssecResolverHost} host
     * @param {DnssecValidatorOptions} options
     */
    public constructor(host: DnssecResolverHost, options: DnssecValidatorOptions) {
        this._host = host;
        this._trustAnchors = options.trustAnchors;
        this._mode = options.mode;
        this._verifyOptions = options.verifyOptions;
        this._zoneSecurity = new Map();
    }

    /**
     * Apply DNSSEC validation to a response and adjust the AD bit /
     * rcode accordingly. No-op when called inside an auth-chain
     * sub-resolution (would recurse forever).
     *
     * The validator inspects the *raw* server response (`rawResponse`)
     * because that's where the RRSIG records live — `builtResponse`
     * has already been filtered down to the question's answer plus
     * any CNAME chain, so any RRSIGs at the answer's owner name have
     * been stripped. The AD bit is written onto `builtResponse` so the
     * caller's view matches the answer.
     *
     * @param {Packet} builtResponse
     * @param {Packet} rawResponse
     * @param {string} signingZone
     * @param {ResolveCtx} ctx
     * @return {Promise<Packet>}
     */
    public async finalize(
        builtResponse: Packet,
        rawResponse: Packet,
        signingZone: string,
        ctx: ResolveCtx
    ): Promise<Packet> {
        if (ctx.inAuthChain) {
            return builtResponse;
        }

        const validity = await this._validateResponse(rawResponse, signingZone, ctx);

        if (validity === 'bogus') {
            // RFC 4035 §5.5: a bogus answer surfaces as SERVFAIL.
            return DnssecValidator._buildServfail(ctx);
        }

        if (validity === 'insecure' && this._mode === 'strict') {
            return DnssecValidator._buildServfail(ctx);
        }

        // RFC 4035 §3.2 carved AD (Authentic Data) and CD (Checking
        // Disabled) out of the legacy 3-bit Z field. Bit layout (MSB
        // first): Z, AD, CD. Set AD on validated answers; clear it
        // otherwise.
        // eslint-disable-next-line no-bitwise, no-param-reassign
        builtResponse.header.z = validity === 'secure'
            // eslint-disable-next-line no-bitwise
            ? builtResponse.header.z | 0b010
            // eslint-disable-next-line no-bitwise
            : builtResponse.header.z & ~0b010;
        return builtResponse;
    }

    /**
     * Authenticate every signed RRset in the response and, for negative
     * answers, the NSEC/NSEC3 proof. Returns the overall validity:
     *
     *  - `secure` — every signed RRset verified, negative proof (if any) verified
     *  - `insecure` — chain proves no DS exists at the answer's signing zone
     *  - `bogus` — at least one signature didn't verify, or a proof was missing
     *  - `indeterminate` — no anchor covers the zone (resolver passes through)
     *
     * @protected
     */
    protected async _validateResponse(
        response: Packet,
        signingZone: string,
        ctx: ResolveCtx
    ): Promise<DnssecValidity> {
        const zoneState = await this._authenticateZone(signingZone, ctx);

        if (zoneState.validity !== 'secure') {
            return zoneState.validity;
        }

        const dnskeys = zoneState.dnskeys ?? [];

        // Validate every (non-RRSIG, non-OPT) RRset in the answer + authority.
        const sections = [...response.answers, ...response.authorities];
        const groups = DnssecChain.groupRrsets(sections);
        const rrsigs = DnssecChain.rrsigs(sections);

        for (const [, recs] of groups) {
            const owner = recs[0].name;
            const matchingSigs = DnssecChain.rrsigsFor(rrsigs, owner, recs[0].packetType.type);

            if (matchingSigs.length === 0) {
                // Some sections (e.g. CNAME chains in mixed responses)
                // may not be signed in the same response; the resolver
                // sees only what the auth shipped. Treat as insecure for
                // permissive mode — strict mode escalates upstream.
                continue;
            }

            const r = DnssecChain.validateRrset(owner, recs, matchingSigs, dnskeys, this._verifyOptions);

            if (r.validity === 'bogus') {
                return 'bogus';
            }
        }

        // Negative-proof validation for NXDOMAIN / NODATA shapes.
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
            } else {
                const proven = (nsec.length > 0 && NegativeProof.verifyNodataNsec(qname, qtype as number, nsec))
                    || (nsec3.length > 0 && NegativeProof.verifyNodataNsec3(qname, qtype as number, signingZone, nsec3));

                if (nsec.length + nsec3.length > 0 && !proven) {
                    return 'bogus';
                }
            }
        }

        return 'secure';
    }

    /**
     * Walk the DNSSEC chain from a configured trust anchor down to
     * `zone`, fetching DNSKEY + DS records at each step and validating
     * them. Caches the result in `_zoneSecurity` so subsequent answers
     * within the same zone re-use the authenticated DNSKEY set.
     *
     * @protected
     */
    protected async _authenticateZone(zone: string, ctx: ResolveCtx): Promise<ZoneSecurity> {
        const norm = normZone(zone);
        const cached = this._zoneSecurity.get(norm);

        if (cached !== undefined) {
            return cached;
        }

        const anchor = TrustAnchors.findFor(this._trustAnchors, zone);

        if (anchor === undefined) {
            const out: ZoneSecurity = {validity: 'indeterminate', reason: 'no trust anchor covers zone'};
            this._zoneSecurity.set(norm, out);
            return out;
        }

        // Path from anchor down to zone, e.g. ['', 'com', 'example.com'].
        const path = chainPath(anchor.zone, zone);
        let parentDsList: DS[] = [anchor.ds as DS];

        const subCtx: ResolveCtx = {...ctx, inAuthChain: true};

        let result: ZoneSecurity = {validity: 'indeterminate'};

        for (let i = 0; i < path.length; i++) {
            const step = path[i];
            const stepNorm = normZone(step);
            const stepCached = this._zoneSecurity.get(stepNorm);

            if (stepCached?.validity === 'secure') {
                result = stepCached;

                // Continue chain with this zone's DNSKEYs.
                if (i + 1 < path.length) {
                    // eslint-disable-next-line no-await-in-loop
                    const dsResult = await this._fetchAndValidateDs(path[i + 1], stepCached.dnskeys ?? [], subCtx);

                    if (dsResult.kind === 'secure') {
                        parentDsList = dsResult.ds;
                        continue;
                    }

                    if (dsResult.kind === 'insecure') {
                        const insec: ZoneSecurity = {validity: 'insecure', reason: dsResult.reason};
                        this._zoneSecurity.set(normZone(path[i + 1]), insec);
                        return insec;
                    }

                    const bogus: ZoneSecurity = {validity: 'bogus', reason: dsResult.reason};
                    this._zoneSecurity.set(normZone(path[i + 1]), bogus);
                    return bogus;
                }

                continue;
            }

            if (stepCached?.validity === 'bogus' || stepCached?.validity === 'insecure') {
                return stepCached;
            }

            // Fetch + validate the DNSKEY RRset of `step`. The
            // sub-resolve answer-shape filters down to (qname, qtype),
            // dropping RRSIGs — but `_cacheResponse` already grouped
            // and cached every RRset separately, including RRSIGs at
            // the zone apex. Pull them from the cache instead.
            try {
                // eslint-disable-next-line no-await-in-loop
                await this._host._resolveOnce(step, PacketTypes.DNSKEY, PacketClass.IN, subCtx);
            } catch {
                const bogus: ZoneSecurity = {validity: 'bogus', reason: `failed to fetch DNSKEY for ${step}`};
                this._zoneSecurity.set(stepNorm, bogus);
                return bogus;
            }

            const dnskeyEntry = this._host.cache().get(step, PacketTypes.DNSKEY, PacketClass.IN);
            const rrsigEntry = this._host.cache().get(step, PacketTypes.RRSIG, PacketClass.IN);
            const dnskeys = dnskeyEntry?.records ?? [];
            const dnskeyRrsigs = DnssecChain.rrsigsFor(rrsigEntry?.records ?? [], step, PacketTypes.DNSKEY);

            const validated = DnssecChain.validateDnskeyRrset(
                step,
                dnskeys,
                dnskeyRrsigs,
                parentDsList,
                this._verifyOptions
            );

            if (validated.validity !== 'secure') {
                const bogus: ZoneSecurity = {validity: 'bogus', reason: validated.reason ?? 'DNSKEY validation failed'};
                this._zoneSecurity.set(stepNorm, bogus);
                return bogus;
            }

            const stepSec: ZoneSecurity = {validity: 'secure', dnskeys: dnskeys, rrsigs: dnskeyRrsigs};
            this._zoneSecurity.set(stepNorm, stepSec);
            result = stepSec;

            // For the next step, fetch + validate its DS record.
            if (i + 1 < path.length) {
                // eslint-disable-next-line no-await-in-loop
                const dsResult = await this._fetchAndValidateDs(path[i + 1], dnskeys, subCtx);

                if (dsResult.kind === 'secure') {
                    parentDsList = dsResult.ds;
                    continue;
                }

                if (dsResult.kind === 'insecure') {
                    const insec: ZoneSecurity = {validity: 'insecure', reason: dsResult.reason};
                    this._zoneSecurity.set(normZone(path[i + 1]), insec);
                    return insec;
                }

                const bogus: ZoneSecurity = {validity: 'bogus', reason: dsResult.reason};
                this._zoneSecurity.set(normZone(path[i + 1]), bogus);
                return bogus;
            }
        }

        return result;
    }

    /**
     * Fetch the DS RRset at `zone` (queried against the parent zone)
     * and validate its signature with the parent's DNSKEY set.
     *
     * @protected
     */
    protected async _fetchAndValidateDs(
        zone: string,
        parentDnskeys: PacketResource[],
        ctx: ResolveCtx
    ): Promise<{kind: 'secure'; ds: DS[];} | {kind: 'insecure' | 'bogus'; reason?: string;}> {
        let dsResp: Packet;

        try {
            dsResp = await this._queryDsAtParent(zone, ctx);
        } catch {
            return {kind: 'bogus', reason: `failed to fetch DS for ${zone}`};
        }

        const dsEntry = this._host.cache().get(zone, PacketTypes.DS, PacketClass.IN);
        const rrsigEntry = this._host.cache().get(zone, PacketTypes.RRSIG, PacketClass.IN);

        const dsRecords = dsEntry?.records ?? [];
        const dsRrsigs = DnssecChain.rrsigsFor(rrsigEntry?.records ?? [], zone, PacketTypes.DS);

        if (dsRecords.length === 0) {
            if (dsResp.header.rcode !== RCODE.NOERROR) {
                return {kind: 'bogus', reason: 'DS query did not return NOERROR'};
            }

            // RFC 4035 §5.2 / RFC 5155 §6: a missing-DS claim must be
            // proved with NSEC/NSEC3. Otherwise an attacker who can
            // strip RRSIGs from an empty response would downgrade every
            // signed zone to "insecure" and disable validation entirely.
            const proven = this._verifyInsecureDelegationProof(zone, dsResp, parentDnskeys);

            if (!proven) {
                return {kind: 'bogus', reason: 'no valid NSEC/NSEC3 proof of insecure delegation'};
            }

            return {kind: 'insecure', reason: 'no DS record (insecure delegation, proved)'};
        }

        const validated = DnssecChain.validateRrset(
            zone,
            dsRecords,
            dsRrsigs,
            parentDnskeys,
            this._verifyOptions
        );

        if (validated.validity !== 'secure') {
            return {kind: 'bogus', reason: validated.reason ?? 'DS RRset signature did not verify'};
        }

        return {kind: 'secure', ds: dsRecords.map((r) => r.packetType as DS)};
    }

    /**
     * Verify an "insecure delegation" claim by checking the
     * NSEC/NSEC3 records in the response's authority section against
     * `parentDnskeys` and then running the proof-shape check from
     * `NegativeProof`.
     *
     * @protected
     */
    protected _verifyInsecureDelegationProof(
        delegationName: string,
        response: Packet,
        parentDnskeys: PacketResource[]
    ): boolean {
        const auth = response.authorities;
        const nsecs = auth.filter((r) => r.packetType.type === PacketTypes.NSEC);
        const nsec3s = auth.filter((r) => r.packetType.type === PacketTypes.NSEC3);

        if (nsecs.length === 0 && nsec3s.length === 0) {
            return false;
        }

        // Validate every NSEC/NSEC3 RRset's RRSIGs against the parent
        // DNSKEYs before consulting the proof shape — otherwise an
        // off-path attacker could mint forged NSEC3s with the opt-out
        // bit and downgrade arbitrary zones to insecure.
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

    /**
     * Send a `DS` query for `zone` to the closest NS that is strictly
     * above `zone` — i.e. the parent zone's authority. RFC 4035 §5.2:
     * DS records live at the parent, not the zone itself.
     *
     * Bypasses the host's normal iterative loop because that loop
     * would pick `zone`'s own NS as the closest match (the referral
     * that delivered `zone` already cached its NS RRset).
     *
     * @protected
     */
    protected async _queryDsAtParent(zone: string, ctx: ResolveCtx): Promise<Packet> {
        const parent = parentOf(zone);
        const ns = this._host._findClosestNs(parent, PacketClass.IN);

        if (ns === null) {
            throw new Error(`DnssecValidator: no cached NS for parent of ${zone}`);
        }

        // Walk one step up if the closest NS turned out to BE `zone`
        // itself (the referral cached zone's own NS just before this).
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

    /**
     * Build a SERVFAIL response shaped for the original question,
     * mirroring `RecursiveResolver._buildResponse` for the SERVFAIL
     * case. Kept here so the validator stays self-contained.
     * @protected
     */
    protected static _buildServfail(ctx: ResolveCtx): Packet {
        const out = new Packet();
        out.header.qr = 1;
        out.header.ra = 1;
        out.header.aa = 0;
        out.header.rcode = RCODE.SERVFAIL;
        out.questions.push(new PacketQuestion(ctx.originalQname, ctx.originalQtype, ctx.qclass));
        return out;
    }

}