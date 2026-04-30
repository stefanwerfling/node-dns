import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
export type DnsCacheRcode = 'NOERROR' | 'NXDOMAIN' | 'NODATA';
export type DnsCacheEntry = {
    name: string;
    type: number;
    class: number;
    records: PacketResource[];
    rcode: DnsCacheRcode;
    expiresAt: number;
    stale?: boolean;
};
export type DnsCacheOptions = {
    maxEntries?: number;
    maxTtlSeconds?: number;
    minTtlSeconds?: number;
    maxStaleSeconds?: number;
    now?: () => number;
};
export declare class DnsCache {
    static readonly DEFAULT_MAX_TTL_SECONDS: number;
    static readonly DEFAULT_MAX_ENTRIES: number;
    protected _entries: Map<string, DnsCacheEntry>;
    protected _maxEntries: number;
    protected _maxTtlSeconds: number;
    protected _minTtlSeconds: number;
    protected _maxStaleSeconds: number;
    protected _now: () => number;
    constructor(options?: DnsCacheOptions);
    static key(name: string, type: number, cls: number): string;
    protected static _normalize(name: string): string;
    protected _clampTtl(ttlSeconds: number): number;
    set(name: string, type: number | PacketTypes, cls: number | PacketClass, records: PacketResource[], ttlSeconds: number): void;
    setNegative(name: string, type: number | PacketTypes, cls: number | PacketClass, rcode: 'NXDOMAIN' | 'NODATA', ttlSeconds: number): void;
    get(name: string, type: number | PacketTypes, cls: number | PacketClass): DnsCacheEntry | null;
    size(): number;
    delete(name: string, type: number | PacketTypes, cls: number | PacketClass): void;
    clear(): void;
    protected _insert(entry: DnsCacheEntry): void;
}
