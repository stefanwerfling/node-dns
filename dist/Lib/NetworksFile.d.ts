import { Buffer } from 'buffer';
export type NetworksEntry = {
    name: string;
    address: string;
    aliases: string[];
};
export type NetworksFileOptions = {
    path?: string;
};
export declare class NetworksFile {
    static readonly DEFAULT_PATH: string;
    protected _entries: NetworksEntry[];
    protected _byName: Map<string, NetworksEntry>;
    protected _byAddress: Map<string, NetworksEntry>;
    protected _sourcePath: string | null;
    constructor(entries?: NetworksEntry[], sourcePath?: string | null);
    static parse(content: string): NetworksFile;
    static fromFile(path?: string): NetworksFile;
    protected static _expandAddress(address: string): string | null;
    get entries(): NetworksEntry[];
    get sourcePath(): string | null;
    lookupByName(name: string): NetworksEntry | null;
    lookupByAddress(address: string | Buffer): NetworksEntry | null;
    merge(other: NetworksFile): NetworksFile;
}
