import { DnssecVerifyOptions } from '../Lib/Dnssec.js';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { DS } from '../Packet/Types/DS.js';
import { DnsCache } from './DnsCache.js';
import { DnssecValidity } from './DnssecChain.js';
import type { ResolveCtx } from './RecursiveResolver.js';
import { TrustAnchor } from './TrustAnchor.js';
export type DnssecMode = 'strict' | 'permissive';
export type DnssecValidatorOptions = {
    trustAnchors: ReadonlyArray<TrustAnchor>;
    mode: DnssecMode;
    verifyOptions: DnssecVerifyOptions;
};
export interface DnssecResolverHost {
    cache(): DnsCache;
    _resolveOnce(qname: string, qtype: number | PacketTypes, qclass: PacketClass, ctx: ResolveCtx): Promise<Packet>;
    _queryServer(serverIp: string, qname: string, qtype: number | PacketTypes, qclass: PacketClass, ctx: ResolveCtx): Promise<Packet>;
    _findClosestNs(qname: string, qclass: PacketClass): {
        zone: string;
        ns: PacketResource[];
    } | null;
    _pickNsAddress(nsZone: {
        zone: string;
        ns: PacketResource[];
    }, qclass: PacketClass, ctx: ResolveCtx): Promise<string | null>;
    _cacheResponse(response: Packet, zone: string): void;
}
type ZoneSecurity = {
    validity: DnssecValidity;
    dnskeys?: PacketResource[];
    rrsigs?: PacketResource[];
    reason?: string;
};
export declare class DnssecValidator {
    protected _host: DnssecResolverHost;
    protected _trustAnchors: ReadonlyArray<TrustAnchor>;
    protected _mode: DnssecMode;
    protected _verifyOptions: DnssecVerifyOptions;
    protected _zoneSecurity: Map<string, ZoneSecurity>;
    constructor(host: DnssecResolverHost, options: DnssecValidatorOptions);
    finalize(builtResponse: Packet, rawResponse: Packet, signingZone: string, ctx: ResolveCtx): Promise<Packet>;
    protected _validateResponse(response: Packet, signingZone: string, ctx: ResolveCtx): Promise<DnssecValidity>;
    protected _authenticateZone(zone: string, ctx: ResolveCtx): Promise<ZoneSecurity>;
    protected _fetchAndValidateDs(zone: string, parentDnskeys: PacketResource[], ctx: ResolveCtx): Promise<{
        kind: 'secure';
        ds: DS[];
    } | {
        kind: 'insecure' | 'bogus';
        reason?: string;
    }>;
    protected _verifyInsecureDelegationProof(delegationName: string, response: Packet, parentDnskeys: PacketResource[]): boolean;
    protected _queryDsAtParent(zone: string, ctx: ResolveCtx): Promise<Packet>;
    protected static _buildServfail(ctx: ResolveCtx): Packet;
}
export {};
