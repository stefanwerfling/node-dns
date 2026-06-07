import { Buffer } from 'buffer';
import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
export declare class CERT extends PacketType {
    certType: number;
    keyTag: number;
    algorithm: number;
    certificate: string;
    constructor(certType?: number, keyTag?: number, algorithm?: number, certificate?: string);
    encode(_resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader, length: number): PacketType;
}
