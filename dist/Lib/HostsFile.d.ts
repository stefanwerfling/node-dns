import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
export type HostsEntry = {
    address: string;
    family: 'ipv4' | 'ipv6';
    names: string[];
};
export type HostsLookupResult = {
    kind: 'match';
    records: PacketResource[];
} | {
    kind: 'nodata';
} | {
    kind: 'miss';
};
export type HostsFileOptions = {
    ttl?: number;
};
export declare class HostsFile {
    static readonly DEFAULT_PATH: string;
    protected _entries: HostsEntry[];
    protected _byName: Map<string, HostsEntry[]>;
    protected _ttl: number;
    constructor(entries?: HostsEntry[], options?: HostsFileOptions);
    static parse(content: string, options?: HostsFileOptions): HostsFile;
    static fromFile(path?: string, options?: HostsFileOptions): HostsFile;
    get entries(): HostsEntry[];
    lookup(name: string, type: PacketTypes | number): HostsLookupResult;
    asResolverBackend(fallback: (name: string, type: PacketTypes | number, cls: PacketClass | number) => Promise<Packet>): (name: string, type: PacketTypes | number, cls: PacketClass | number) => Promise<Packet>;
    merge(other: HostsFile): HostsFile;
    private static _index;
    private static _normalizeName;
    private static _stripComment;
    private static _detectFamily;
    private static _isIpv4;
    private static _isIpv6;
}
