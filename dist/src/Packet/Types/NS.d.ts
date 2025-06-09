import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
export declare class NS extends PacketType {
    ns: string;
    constructor(ns?: string);
    encode(resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader): PacketType;
}
