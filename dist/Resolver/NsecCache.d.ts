import { Buffer } from 'buffer';
import { Packet } from '../Packet/Packet.js';
export type CachedNsec = {
    owner: string;
    nextDomain: string;
    types: Set<number>;
    ttl: number;
    expiresAt: number;
};
export type CachedNsec3 = {
    ownerHash: Buffer;
    nextHash: Buffer;
    flags: number;
    types: Set<number>;
    ttl: number;
    expiresAt: number;
};
export type Nsec3Params = {
    salt: string;
    iterations: number;
};
export type SynthesizedNegative = {
    kind: 'nodata';
    ttl: number;
} | {
    kind: 'nxdomain';
    ttl: number;
};
export type NsecCacheOptions = {
    now?: () => number;
    maxEntries?: number;
};
export declare class NsecCache {
    protected _nsecByZone: Map<string, CachedNsec[]>;
    protected _nsec3ByZone: Map<string, CachedNsec3[]>;
    protected _nsec3Params: Map<string, Nsec3Params>;
    protected _now: () => number;
    protected _maxEntries: number;
    protected _totalNsec: number;
    protected _totalNsec3: number;
    protected _insertionOrder: Array<{
        zone: string;
        kind: 'nsec' | 'nsec3';
        idx: number;
    }>;
    constructor(options?: NsecCacheOptions);
    forgetZone(zone: string): void;
    clear(): void;
    size(): number;
    storeFromResponse(packet: Packet, zone: string): void;
    proveNegative(qname: string, qtype: number): SynthesizedNegative | null;
    setNsec3Params(zone: string, params: Nsec3Params): void;
    getNsec3Params(zone: string): Nsec3Params | null;
    protected static _zoneKey(zone: string): string;
    protected static _nameKey(name: string): string;
    protected _storeRecord(owner: string, ttl: number, packetType: unknown, zone: string): void;
    protected _evictIfNeeded(): void;
    protected _proveNodataViaNsec(qname: string, qtype: number): SynthesizedNegative | null;
    protected _proveNxdomainViaNsec(qname: string): SynthesizedNegative | null;
    protected _proveNxdomainViaNsec3(qname: string): SynthesizedNegative | null;
    protected _proveNodataViaNsec3(qname: string, qtype: number): SynthesizedNegative | null;
    protected static _closestEncloser(qname: string, owner: string, next: string, zone: string): string | null;
    protected static _decodeBase32Hex(input: string): Buffer | null;
    protected static _remainingSeconds(expiresAt: number, now: number): number;
}
