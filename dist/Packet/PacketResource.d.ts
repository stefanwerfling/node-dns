import { Buffer } from 'buffer';
import { BufferReader } from '../Lib/BufferReader.js';
import { BufferWriter } from '../Lib/BufferWriter.js';
import { PacketClass } from './PacketClass.js';
import { PacketType } from './PacketType.js';
import { PacketTypes } from './PacketTypes.js';
export declare class UnknownPacketType extends PacketType {
    data: Buffer;
    constructor(type: PacketTypes | number, data?: Buffer);
    encode(_resource: PacketResource, writer?: BufferWriter | null): Buffer;
}
export declare class PacketResource {
    name: string;
    packetType: PacketType;
    class: PacketClass | number;
    ttl: number;
    constructor(name: string, packetType: PacketType, cls?: PacketClass | number, ttl?: number);
    toBuffer(writer?: BufferWriter | null): Buffer;
    static encode(resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader | Buffer): PacketResource;
}
