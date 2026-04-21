import { Buffer } from 'buffer';
import { Packet } from './Packet.js';
import { TsigKey } from './TsigKey.js';
import { TSIG } from './Types/TSIG.js';
export type TsigSignOptions = {
    timeSigned?: number;
    fudge?: number;
    requestMac?: Buffer;
    error?: number;
    otherData?: Buffer;
};
export type TsigSignResult = {
    buffer: Buffer;
    mac: Buffer;
    tsig: TSIG;
};
export type TsigVerifyOptions = {
    requestMac?: Buffer;
    now?: number;
    skipTimeCheck?: boolean;
};
export type TsigVerifyResult = {
    valid: boolean;
    reason?: string;
    tsig?: TSIG;
};
export declare class Tsig {
    protected static readonly ARCOUNT_OFFSET: number;
    protected static canonicalName(name: string): string;
    static hashName(algorithm: string): string;
    protected static encodeTsigVariables(keyName: string, algorithm: string, timeSigned: number, fudge: number, error: number, otherData: Buffer): Buffer;
    protected static encodeRequestMacPrefix(mac: Buffer): Buffer;
    static sign(packet: Packet, key: TsigKey, options?: TsigSignOptions): TsigSignResult;
    static verify(packet: Packet, receivedBytes: Buffer, key: TsigKey, options?: TsigVerifyOptions): TsigVerifyResult;
}
