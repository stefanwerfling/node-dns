import { Buffer } from 'buffer';
import { PacketHeader } from '../Packet/PacketHeader.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { BufferReader } from './BufferReader.js';
import { BufferWriter } from './BufferWriter.js';
export declare enum DsoTlvType {
    KEEPALIVE = 0,
    RETRY_DELAY = 1,
    ENCRYPTION_PADDING = 2,
    SUBSCRIBE = 64,
    PUSH = 65,
    UNSUBSCRIBE = 66,
    RECONFIRM = 67
}
export declare const DSO_UNILATERAL_MESSAGE_ID: number;
export interface DsoTlv {
    readonly type: number;
    encode(writer: BufferWriter): void;
}
export declare class KeepaliveTlv implements DsoTlv {
    readonly type: number;
    inactivityMs: number;
    keepaliveMs: number;
    constructor(inactivityMs: number, keepaliveMs: number);
    encode(writer: BufferWriter): void;
    static decode(reader: BufferReader, length: number): KeepaliveTlv;
}
export declare class RetryDelayTlv implements DsoTlv {
    readonly type: number;
    retryDelayMs: number;
    constructor(retryDelayMs: number);
    encode(writer: BufferWriter): void;
    static decode(reader: BufferReader, length: number): RetryDelayTlv;
}
export declare class EncryptionPaddingTlv implements DsoTlv {
    readonly type: number;
    padding: Buffer;
    constructor(padding: Buffer);
    encode(writer: BufferWriter): void;
    static decode(reader: BufferReader, length: number): EncryptionPaddingTlv;
}
export declare class SubscribeTlv implements DsoTlv {
    readonly type: number;
    name: string;
    qtype: number;
    qclass: number;
    constructor(name: string, qtype: number, qclass: number);
    encode(writer: BufferWriter): void;
    static decode(reader: BufferReader, length: number): SubscribeTlv;
}
export declare class PushTlv implements DsoTlv {
    readonly type: number;
    records: PacketResource[];
    constructor(records?: PacketResource[]);
    encode(writer: BufferWriter): void;
    static decode(reader: BufferReader, length: number): PushTlv;
}
export declare class UnsubscribeTlv implements DsoTlv {
    readonly type: number;
    originalMessageId: number;
    constructor(originalMessageId: number);
    encode(writer: BufferWriter): void;
    static decode(reader: BufferReader, length: number): UnsubscribeTlv;
}
export declare class ReconfirmTlv implements DsoTlv {
    readonly type: number;
    name: string;
    qtype: number;
    qclass: number;
    rdata: Buffer;
    constructor(name: string, qtype: number, qclass: number, rdata: Buffer);
    encode(writer: BufferWriter): void;
    static decode(reader: BufferReader, length: number): ReconfirmTlv;
}
export declare class UnknownDsoTlv implements DsoTlv {
    readonly type: number;
    data: Buffer;
    constructor(type: number, data: Buffer);
    encode(writer: BufferWriter): void;
    static decode(reader: BufferReader, type: number, length: number): UnknownDsoTlv;
}
export declare class DsoMessage {
    header: PacketHeader;
    tlvs: DsoTlv[];
    constructor(header?: PacketHeader, tlvs?: DsoTlv[]);
    static request(messageId: number, primaryTlv: DsoTlv, ...additional: DsoTlv[]): DsoMessage;
    static unilateral(primaryTlv: DsoTlv, ...additional: DsoTlv[]): DsoMessage;
    static response(messageId: number, rcode?: number, tlvs?: DsoTlv[]): DsoMessage;
    toBuffer(): Buffer;
    static parse(buffer: Buffer): DsoMessage;
    protected static _decodeTlv(reader: BufferReader, type: number, length: number): DsoTlv;
    get primary(): DsoTlv | undefined;
}
