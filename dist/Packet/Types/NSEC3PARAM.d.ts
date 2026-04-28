import { Buffer } from 'buffer';
import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
export declare class NSEC3PARAM extends PacketType {
    hashAlgorithm: number;
    flags: number;
    iterations: number;
    salt: string;
    constructor(hashAlgorithm?: number, flags?: number, iterations?: number, salt?: string);
    encode(_resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader, _length: number): PacketType;
}
