import type { ParsedResolvConf } from '../Lib/ResolvConf.js';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
export type StubResolverBackend = (name: string, type: PacketTypes | number, cls: PacketClass | number) => Promise<Packet>;
export type StubResolverOptions = {
    resolver: StubResolverBackend;
    search?: string[];
    ndots?: number;
};
export declare class StubResolver {
    protected _resolver: StubResolverBackend;
    protected _search: string[];
    protected _ndots: number;
    constructor(options: StubResolverOptions);
    static fromConfig(parsed: ParsedResolvConf, resolver: StubResolverBackend): StubResolver;
    expand(name: string): string[];
    resolve(name: string, type: PacketTypes | number, cls?: PacketClass | number): Promise<Packet>;
    get search(): string[];
    get ndots(): number;
    protected static _normalizeSearch(list: string[]): string[];
    protected static _countDots(name: string): number;
}
