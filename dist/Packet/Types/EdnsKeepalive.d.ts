import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { EdnsOption } from './EdnsECS.js';
export declare class EdnsKeepalive implements EdnsOption {
    ednsCode: number;
    timeout: number | null;
    constructor(timeout?: number | null);
    static decode(reader: BufferReader, length: number): EdnsKeepalive;
    encode(writer: BufferWriter): void;
}
