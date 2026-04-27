import { Buffer } from 'buffer';
import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { EdnsOption } from './EdnsECS.js';
export declare class EdnsNsid implements EdnsOption {
    ednsCode: number;
    data: Buffer;
    constructor(data?: Buffer | string);
    static decode(reader: BufferReader, length: number): EdnsNsid;
    encode(writer: BufferWriter): void;
}
