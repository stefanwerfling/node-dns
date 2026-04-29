import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { DnsCache } from './DnsCache.js';
import { RootServer } from './RootHints.js';
export declare const RCODE: {
    readonly NOERROR: 0;
    readonly FORMERR: 1;
    readonly SERVFAIL: 2;
    readonly NXDOMAIN: 3;
    readonly NOTIMP: 4;
    readonly REFUSED: 5;
};
export type RecursiveResolverTransport = (serverIp: string, port: number, query: Packet) => Promise<Packet>;
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
    protected _cacheResponse(response: Packet, zone: string): void;
    protected _handleAnswer(response: Packet, qname: string, qtype: number | PacketTypes, qclass: PacketClass, ctx: ResolveCtx): Promise<Packet>;
    protected _followCnameFromCache(qname: string, qtype: number | PacketTypes, qclass: PacketClass, ctx: ResolveCtx, cnameRecords: PacketResource[]): Promise<Packet>;
    protected _referralZone(response: Packet, currentZone: string): string | null;
    protected _guardBudget(ctx: ResolveCtx): void;
    protected static _defaultUdpTransport(serverIp: string, port: number, query: Packet): Promise<Packet>;
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
};
export {};
