import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
export declare enum EdnsOptionCode {
    ECS = 8
}
export interface EdnsOption {
    ednsCode: number;
}
export declare class EdnsECS implements EdnsOption {
    ednsCode: number;
    family: number;
    sourcePrefixLength: number;
    scopePrefixLength: number;
    ip: string;
    constructor(clientIp?: string);
    static decode(reader: BufferReader, length: number): EdnsECS;
    encode(writer: BufferWriter): void;
}
