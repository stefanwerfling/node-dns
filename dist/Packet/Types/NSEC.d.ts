import { Buffer } from 'buffer';
import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
export declare class NSEC extends PacketType {
    nextDomain: string;
    rdtypes: number[];
    constructor(nextDomain?: string, rdtypes?: number[]);
    private static _decodeTypeBitMaps;
    private static _encodeTypeBitMaps;
    encode(_resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader, length: number): PacketType;
}
