import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { DnsCache, DnsCacheOptions } from './DnsCache.js';
import type { StubResolverBackend } from './StubResolver.js';
export type CachedStubBackendOptions = {
    cache?: DnsCache;
    cacheOptions?: DnsCacheOptions;
    isCacheable?: (response: Packet) => boolean;
    now?: () => number;
};
export declare class CachedStubBackend {
    protected _upstream: StubResolverBackend;
    protected _cache: DnsCache;
    protected _isCacheable: (response: Packet) => boolean;
    protected _refreshInFlight: Set<string>;
    protected _now: () => number;
    constructor(upstream: StubResolverBackend, options?: CachedStubBackendOptions);
    resolve: StubResolverBackend;
    get cache(): DnsCache;
    protected _buildResponse(qname: string, qtype: PacketTypes | number, qclass: PacketClass | number, entry: {
        records: PacketResource[];
        rcode: string;
        cachedAt: number;
        expiresAt: number;
    }): Packet;
    protected static _cloneWithAdjustedTtl(r: PacketResource, cachedAt: number, now: number): PacketResource;
    protected _maybeStore(qname: string, qtype: PacketTypes | number, qclass: PacketClass | number, response: Packet): void;
    protected _scheduleRefresh(qname: string, qtype: PacketTypes | number, qclass: PacketClass | number): void;
}
