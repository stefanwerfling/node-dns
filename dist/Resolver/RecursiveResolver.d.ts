import { DnssecVerifyOptions } from '../Lib/Dnssec.js';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { DS } from '../Packet/Types/DS.js';
import { DnsCache } from './DnsCache.js';
import { DnssecValidity } from './DnssecChain.js';
import { RootServer } from './RootHints.js';
import { TrustAnchor } from './TrustAnchor.js';
export declare const RCODE: {
    readonly NOERROR: 0;
    readonly FORMERR: 1;
    readonly SERVFAIL: 2;
    readonly NXDOMAIN: 3;
    readonly NOTIMP: 4;
    readonly REFUSED: 5;
};
export type RecursiveResolverTransport = (serverIp: string, port: number, query: Packet) => Promise<Packet>;
export type DnssecMode = 'strict' | 'permissive';
export type DnssecResolverOptions = {
    trustAnchors?: ReadonlyArray<TrustAnchor>;
    mode?: DnssecMode;
    verifyOptions?: DnssecVerifyOptions;
};
export type RecursiveResolverOptions = {
    cache?: DnsCache;
    rootHints?: ReadonlyArray<RootServer>;
    transport?: RecursiveResolverTransport;
    use0x20?: boolean;
    timeoutMs?: number;
    queryTimeoutMs?: number;
    maxQueries?: number;
    maxCnameDepth?: number;
    port?: number;
    tcpFallback?: boolean;
    tcpPort?: number;
    tcpTransport?: RecursiveResolverTransport;
    useEdns?: boolean;
    udpPayloadSize?: number;
    dnssec?: boolean | DnssecResolverOptions;
};
export type ResolveOptions = {
    qclass?: PacketClass;
    timeoutMs?: number;
    queryTimeoutMs?: number;
    maxQueries?: number;
    maxCnameDepth?: number;
};
export declare class RecursiveResolver {
    protected _cache: DnsCache;
    protected _transport: RecursiveResolverTransport;
    protected _use0x20: boolean;
    protected _timeoutMs: number;
    protected _queryTimeoutMs: number;
    protected _maxQueries: number;
    protected _maxCnameDepth: number;
    protected _port: number;
    protected _tcpFallback: boolean;
    protected _tcpPort: number;
    protected _tcpTransport: RecursiveResolverTransport;
    protected _useEdns: boolean;
    protected _udpPayloadSize: number;
    protected _dnssecEnabled: boolean;
    protected _trustAnchors: ReadonlyArray<TrustAnchor>;
    protected _dnssecMode: DnssecMode;
    protected _dnssecVerifyOptions: DnssecVerifyOptions;
    protected _zoneSecurity: Map<string, ZoneSecurity>;
    constructor(options?: RecursiveResolverOptions);
    cache(): DnsCache;
    resolve(qname: string, qtype: number | PacketTypes, options?: ResolveOptions): Promise<Packet>;
    protected _resolveOnce(qname: string, qtype: number | PacketTypes, qclass: PacketClass, ctx: ResolveCtx): Promise<Packet>;
    protected _findClosestNs(qname: string, qclass: PacketClass): {
        zone: string;
        ns: PacketResource[];
    } | null;
    protected _pickNsAddress(nsZone: {
        zone: string;
        ns: PacketResource[];
    }, qclass: PacketClass, ctx: ResolveCtx): Promise<string | null>;
    protected _queryServer(serverIp: string, qname: string, qtype: number | PacketTypes, qclass: PacketClass, ctx: ResolveCtx): Promise<Packet>;
    protected _sendAndVerify(transport: RecursiveResolverTransport, port: number, serverIp: string, query: Packet, sentName: string, ctx: ResolveCtx): Promise<Packet>;
    protected _cacheResponse(response: Packet, zone: string): void;
    protected _handleAnswer(response: Packet, qname: string, qtype: number | PacketTypes, qclass: PacketClass, ctx: ResolveCtx): Promise<Packet>;
    protected _followCnameFromCache(qname: string, qtype: number | PacketTypes, qclass: PacketClass, ctx: ResolveCtx, cnameRecords: PacketResource[]): Promise<Packet>;
    protected _referralZone(response: Packet, currentZone: string): string | null;
    protected _guardBudget(ctx: ResolveCtx): void;
    protected _dnssecFinalize(builtResponse: Packet, rawResponse: Packet, signingZone: string, ctx: ResolveCtx): Promise<Packet>;
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
    protected static _parentOf(zone: string): string;
    protected static _defaultUdpTransport(serverIp: string, port: number, query: Packet): Promise<Packet>;
    protected static _defaultTcpTransport(serverIp: string, port: number, query: Packet): Promise<Packet>;
    protected static _withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T>;
    protected static _buildResponse(ctx: ResolveCtx, rcode: number, answers: PacketResource[], authorities: PacketResource[]): Packet;
    protected static _cacheEntryToResponse(ctx: ResolveCtx, entry: {
        records: PacketResource[];
        rcode: 'NOERROR' | 'NXDOMAIN' | 'NODATA';
    }): Packet;
    protected static _minTtl(records: PacketResource[]): number;
    protected static _negativeTtl(soa: PacketResource[]): number;
    protected static _extractSoa(packet: Packet): PacketResource[];
    protected static _labels(name: string): string[];
    protected static _nameEquals(a: string, b: string): boolean;
    protected static _normZone(zone: string): string;
    protected static _chainPath(anchorZone: string, target: string): string[];
    protected static _isStrictlyDeeper(child: string, parent: string): boolean;
}
type ResolveCtx = {
    startTime: number;
    timeoutMs: number;
    queryTimeoutMs: number;
    maxQueries: number;
    maxCnameDepth: number;
    queriesIssued: number;
    cnameDepth: number;
    chain: PacketResource[];
    visited: Set<string>;
    originalQname: string;
    originalQtype: number | PacketTypes;
    qclass: PacketClass;
    inAuthChain?: boolean;
};
type ZoneSecurity = {
    validity: DnssecValidity;
    dnskeys?: PacketResource[];
    rrsigs?: PacketResource[];
    reason?: string;
};
export {};
