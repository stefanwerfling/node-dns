import { Buffer } from 'buffer';
import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
export declare class SRV extends PacketType {
    priority: number;
    weight: number;
    port: number;
    target: string;
    constructor(priority?: number, weight?: number, port?: number, target?: string);
    encode(_resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader): PacketType;
}
