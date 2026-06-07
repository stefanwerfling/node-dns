import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { EdnsOption } from './EdnsECS.js';
export declare class EdnsChain implements EdnsOption {
    ednsCode: number;
    closestTrustPoint: string;
    constructor(closestTrustPoint?: string);
    static decode(reader: BufferReader, length: number): EdnsChain;
    encode(writer: BufferWriter): void;
}
