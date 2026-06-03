import fs from 'fs';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
export type HostsEntry = {
    address: string;
    family: 'ipv4' | 'ipv6';
    names: string[];
};
export type HostsFileWatchOptions = {
    path?: string;
    debounceMs?: number;
    onReload?: (file: HostsFile) => void;
    onError?: (err: NodeJS.ErrnoException) => void;
};
export declare class HostsFileWatchHandle {
    protected _hostsFile: HostsFile;
    protected _path: string;
    protected _debounceMs: number;
    protected _onReload?: (file: HostsFile) => void;
    protected _onError?: (err: NodeJS.ErrnoException) => void;
    protected _watcher: fs.FSWatcher | null;
    protected _debounceTimer: NodeJS.Timeout | null;
    protected _closed: boolean;
    constructor(hostsFile: HostsFile, path: string, options: HostsFileWatchOptions);
    get path(): string;
    get closed(): boolean;
    reloadNow(): void;
    close(): void;
    protected _openWatcher(): void;
    protected _scheduleReload(eventType: string): void;
    protected _performReload(): void;
    protected _reportError(err: NodeJS.ErrnoException): void;
}
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
    protected _sourcePath: string | null;
    constructor(entries?: HostsEntry[], options?: HostsFileOptions);
    static parse(content: string, options?: HostsFileOptions): HostsFile;
    static fromFile(path?: string, options?: HostsFileOptions): HostsFile;
    get sourcePath(): string | null;
    reload(path?: string): void;
    get entries(): HostsEntry[];
    lookup(name: string, type: PacketTypes | number): HostsLookupResult;
    asResolverBackend(fallback: (name: string, type: PacketTypes | number, cls: PacketClass | number) => Promise<Packet>): (name: string, type: PacketTypes | number, cls: PacketClass | number) => Promise<Packet>;
    merge(other: HostsFile): HostsFile;
    watch(options?: HostsFileWatchOptions): HostsFileWatchHandle;
    private static _index;
    private static _normalizeName;
    private static _stripComment;
    private static _detectFamily;
    private static _isIpv4;
    private static _isIpv6;
}
