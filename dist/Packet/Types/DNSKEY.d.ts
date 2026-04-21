import { Buffer } from 'buffer';
import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
export declare class DNSKEY extends PacketType {
    flags: number;
    protocol: number;
    algorithm: number;
    keyTag: number;
    zoneKey: boolean;
    zoneSep: boolean;
    key: string;
    constructor(flags?: number, protocol?: number, algorithm?: number, key?: string);
    encode(_resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader, length: number): PacketType;
}
