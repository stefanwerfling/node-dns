import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
export declare enum EdnsOptionCode {
    NSID = 3,
    ECS = 8,
    COOKIE = 10,
    KEEPALIVE = 11,
    PADDING = 12,
    CHAIN = 13,
    EDE = 15
}
export interface EdnsOption {
    ednsCode: number;
    encode(writer: BufferWriter): void;
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
