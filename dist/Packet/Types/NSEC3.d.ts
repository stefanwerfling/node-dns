import { Buffer } from 'buffer';
import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
export declare class NSEC3 extends PacketType {
    hashAlgorithm: number;
    flags: number;
    iterations: number;
    salt: string;
    nextHashedOwner: string;
    rdtypes: number[];
    constructor(hashAlgorithm?: number, flags?: number, iterations?: number, salt?: string, nextHashedOwner?: string, rdtypes?: number[]);
    encode(_resource: PacketResource, writer?: BufferWriter | null): Buffer;
    private static _encodeTypeBitMaps;
    private static _decodeTypeBitMaps;
    static decode(reader: BufferReader, length: number): PacketType;
}
