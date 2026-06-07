import { EventEmitter } from 'events';
import { PacketResource } from '../Packet/PacketResource.js';
import { DNSKEY } from '../Packet/Types/DNSKEY.js';
import { TrustAnchor } from './TrustAnchor.js';
export type KeyState = 'AddPending' | 'Valid' | 'Missing' | 'Revoked' | 'Removed';
export type ManagedKey = {
    keyTag: number;
    flags: number;
    algorithm: number;
    key: string;
    state: KeyState;
    addedAt: number;
    lastSeenAt: number;
    stateChangedAt: number;
};
export type RolloverEvent = {
    type: 'added' | 'promoted' | 'missing' | 'restored' | 'revoked' | 'removed' | 'observed';
    zone: string;
    keyTag: number;
};
export type TrustAnchorManagerOptions = {
    initialAnchors?: ReadonlyArray<TrustAnchor>;
    initialKeys?: ReadonlyArray<{
        zone: string;
        key: ManagedKey;
    }>;
    addHoldDownMs?: number;
    removeHoldDownMs?: number;
    digestType?: number;
    now?: () => number;
};
export type SerializedTrustAnchorState = {
    version: 1;
    keys: Array<{
        zone: string;
        key: ManagedKey;
    }>;
};
export declare class TrustAnchorManager extends EventEmitter {
    protected _initialAnchors: ReadonlyArray<TrustAnchor>;
    protected _addHoldDownMs: number;
    protected _removeHoldDownMs: number;
    protected _digestType: number;
    protected _now: () => number;
    protected _byZone: Map<string, ManagedKey[]>;
    protected _seeded: Set<string>;
    constructor(options?: TrustAnchorManagerOptions);
    static fromSerialized(state: SerializedTrustAnchorState, options?: Omit<TrustAnchorManagerOptions, 'initialKeys'>): TrustAnchorManager;
    serialize(): SerializedTrustAnchorState;
    update(zone: string, records: ReadonlyArray<PacketResource>): RolloverEvent[];
    currentAnchors(zone: string): TrustAnchor[];
    getKeys(zone: string): ManagedKey[];
    forgetZone(zone: string): void;
    protected static _reifyDnskey(key: ManagedKey): DNSKEY;
    protected static _normZone(zone: string): string;
}
