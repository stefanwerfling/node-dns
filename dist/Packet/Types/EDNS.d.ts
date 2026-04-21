import { Buffer } from 'buffer';
import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
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
export declare class EDNS extends PacketType {
    rdata: EdnsOption[];
    constructor(rdata?: EdnsOption[]);
    static createResource(rdata: EdnsOption[]): PacketResource;
    encode(_resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader, length: number): PacketType;
}
