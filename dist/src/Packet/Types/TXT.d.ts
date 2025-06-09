import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export declare class TXT extends PacketType {
    data: string;
    constructor(data?: string, type?: PacketTypes);
    encode(resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader, length: number): PacketType;
}
