import { Buffer } from 'buffer';
import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
export declare class SOA extends PacketType {
    primary: string;
    admin: string;
    serial: number;
    refresh: number;
    retry: number;
    expiration: number;
    minimum: number;
    constructor(primary?: string, admin?: string, serial?: number, refresh?: number, retry?: number, expiration?: number, minimum?: number);
    encode(_resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader): PacketType;
}
