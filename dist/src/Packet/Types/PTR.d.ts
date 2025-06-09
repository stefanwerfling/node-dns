import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
export declare class PTR extends PacketType {
    domain: string;
    constructor(domain?: string);
    encode(resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader): PacketType;
}
