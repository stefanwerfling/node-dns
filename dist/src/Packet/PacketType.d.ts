import { BufferReader } from '../Lib/BufferReader.js';
import { BufferWriter } from '../Lib/BufferWriter.js';
import { PacketResource } from './PacketResource.js';
import { PacketTypes } from './PacketTypes.js';
export declare abstract class PacketType {
    type: PacketTypes | number;
    protected constructor(type: PacketTypes | number);
    encode(resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader, length: number): PacketType;
}
