import { Buffer } from 'buffer';
import { BufferReader } from '../Lib/BufferReader.js';
import { BufferWriter } from '../Lib/BufferWriter.js';
import { PacketClass } from './PacketClass.js';
import { PacketType } from './PacketType.js';
export declare class PacketResource {
    name: string;
    packetType: PacketType;
    class: PacketClass | number;
    ttl: number;
    byteStart?: number;
    rdlength?: number;
    constructor(name: string, packetType: PacketType, cls?: PacketClass | number, ttl?: number);
    toBuffer(writer?: BufferWriter | null): Buffer;
    static encode(resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader | Buffer): PacketResource;
}
