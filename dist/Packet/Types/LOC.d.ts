import { Buffer } from 'buffer';
import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
export declare class LOC extends PacketType {
    version: number;
    size: number;
    horizPre: number;
    vertPre: number;
    latitude: number;
    longitude: number;
    altitude: number;
    constructor(version?: number, size?: number, horizPre?: number, vertPre?: number, latitude?: number, longitude?: number, altitude?: number);
    encode(_resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader, length: number): PacketType;
}
