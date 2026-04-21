import { Buffer } from 'buffer';
import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
export declare enum SvcParamKey {
    mandatory = 0,
    alpn = 1,
    noDefaultAlpn = 2,
    port = 3,
    ipv4hint = 4,
    ech = 5,
    ipv6hint = 6,
    dohpath = 7
}
export type SvcParamUnknown = {
    key: number;
    value: Buffer;
};
export type SvcParams = {
    mandatory?: number[];
    alpn?: string[];
    noDefaultAlpn?: boolean;
    port?: number;
    ipv4hint?: string[];
    ech?: Buffer;
    ipv6hint?: string[];
    dohpath?: string;
    unknown?: SvcParamUnknown[];
};
type SvcParamEntry = {
    key: number;
    value: Buffer;
};
export declare class SVCB extends PacketType {
    priority: number;
    target: string;
    params: SvcParams;
    constructor(priority?: number, target?: string, params?: SvcParams);
    protected static buildEntries(params: SvcParams): SvcParamEntry[];
    protected static encodeUint16List(keys: number[]): Buffer;
    protected static decodeUint16List(buf: Buffer): number[];
    protected static encodeAlpnList(alpns: string[]): Buffer;
    protected static decodeAlpnList(buf: Buffer): string[];
    protected static encodeIpv4Hints(ips: string[]): Buffer;
    protected static decodeIpv4Hints(buf: Buffer): string[];
    protected static encodeIpv6Hints(ips: string[]): Buffer;
    protected static decodeIpv6Hints(buf: Buffer): string[];
    protected static encodeRdata(priority: number, target: string, params: SvcParams): Buffer;
    protected static readBytes(reader: BufferReader, byteCount: number): Buffer;
    protected static decodeParams(reader: BufferReader, bytesTotal: number): SvcParams;
    protected static decodeInto<T extends SVCB>(reader: BufferReader, length: number, ctor: new (priority: number, target: string, params: SvcParams) => T): T;
    encode(_resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader, length: number): PacketType;
}
export {};
