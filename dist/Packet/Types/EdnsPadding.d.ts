import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { EdnsOption } from './EdnsECS.js';
export declare class EdnsPadding implements EdnsOption {
    ednsCode: number;
    length: number;
    constructor(length?: number);
    static decode(reader: BufferReader, length: number): EdnsPadding;
    encode(writer: BufferWriter): void;
}
