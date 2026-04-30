import { Buffer } from 'buffer';
import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
import { EdnsECS, EdnsOption, EdnsOptionCode } from './EdnsECS.js';
export { EdnsOptionCode, EdnsECS };
export type { EdnsOption };
export declare class EDNS extends PacketType {
    rdata: EdnsOption[];
    constructor(rdata?: EdnsOption[]);
    static createResource(rdata: EdnsOption[], udpPayloadSize?: number): PacketResource;
    encode(_resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader, length: number): PacketType;
    protected static _decodeOption(code: number, length: number, reader: BufferReader): EdnsOption | null;
}
