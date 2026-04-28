import { Buffer } from 'buffer';
import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketResource } from '../PacketResource.js';
import { PacketType } from '../PacketType.js';
export declare class RRSIG extends PacketType {
    sigType: number;
    algorithm: number;
    labels: number;
    originalTtl: number;
    expiration: string;
    inception: string;
    keyTag: number;
    signer: string;
    signature: string;
    constructor(sigType?: number, algorithm?: number, labels?: number, originalTtl?: number, expiration?: string, inception?: string, keyTag?: number, signer?: string, signature?: string);
    private static _dateForSig;
    private static _parseSigDate;
    encode(_resource: PacketResource, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader, length: number): PacketType;
}
