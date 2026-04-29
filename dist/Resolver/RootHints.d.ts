import { PacketResource } from '../Packet/PacketResource.js';
import { DnsCache } from './DnsCache.js';
export type RootServer = {
    name: string;
    ipv4: string;
    ipv6?: string;
};
export type RootHintRecords = {
    ns: PacketResource[];
    glue: PacketResource[];
};
export declare class RootHints {
    static readonly DEFAULT_TTL_SECONDS: number;
    static readonly DEFAULT: ReadonlyArray<RootServer>;
    static toRecords(servers?: ReadonlyArray<RootServer>, ttlSeconds?: number): RootHintRecords;
    static seedCache(cache: DnsCache, servers?: ReadonlyArray<RootServer>, ttlSeconds?: number): void;
    static fromNamedRoot(text: string): RootServer[];
    protected static _fqdn(name: string): string;
}
