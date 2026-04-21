import { Buffer } from 'buffer';
import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
export declare class NAPTR extends PacketType {
    order: number;
    preference: number;
    flags: string;
    services: string;
    regexp: string;
    replacement: string;
    constructor(order?: number, preference?: number, flags?: string, services?: string, regexp?: string, replacement?: string);
    private static _readCharString;
    private static _writeCharString;
    encode(_resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader): PacketType;
}
