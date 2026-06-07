import { Buffer } from 'buffer';
import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
export declare class HINFO extends PacketType {
    cpu: string;
    os: string;
    constructor(cpu?: string, os?: string);
    encode(_resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader, length: number): PacketType;
}
