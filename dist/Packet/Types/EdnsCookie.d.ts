import { Buffer } from 'buffer';
import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { EdnsOption } from './EdnsECS.js';
export declare class EdnsCookie implements EdnsOption {
    ednsCode: number;
    clientCookie: Buffer;
    serverCookie: Buffer | null;
    constructor(clientCookie: Buffer, serverCookie?: Buffer | null);
    static decode(reader: BufferReader, length: number): EdnsCookie;
    encode(writer: BufferWriter): void;
    static generateClientCookie(): Buffer;
    static computeServerCookie(clientCookie: Buffer, clientIp: Buffer, secret: Buffer, timestamp?: number): Buffer;
    static verifyServerCookie(serverCookie: Buffer, clientCookie: Buffer, clientIp: Buffer, secret: Buffer, opts?: {
        maxAgeSeconds?: number;
        now?: number;
    }): boolean;
}
