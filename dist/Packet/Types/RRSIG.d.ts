import { BufferReader } from '../../Lib/BufferReader.js';
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
    constructor();
    private static _dateForSig;
    static decode(reader: BufferReader, length: number): PacketType;
}
