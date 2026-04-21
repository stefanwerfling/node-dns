import { Buffer } from 'buffer';
import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
export declare enum TsigError {
    NOERROR = 0,
    BADSIG = 16,
    BADKEY = 17,
    BADTIME = 18,
    BADTRUNC = 22
}
export declare class TSIG extends PacketType {
    algorithm: string;
    timeSigned: number;
    fudge: number;
    mac: Buffer;
    originalId: number;
    error: number;
    otherData: Buffer;
    constructor(algorithm?: string, timeSigned?: number, fudge?: number, mac?: Buffer, originalId?: number, error?: number, otherData?: Buffer);
    protected static splitUint48(value: number): {
        hi: number;
        lo: number;
    };
    protected static joinUint48(hi: number, lo: number): number;
    encode(_resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader): PacketType;
}
