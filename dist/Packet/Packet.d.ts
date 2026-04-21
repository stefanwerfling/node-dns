import { Buffer } from 'buffer';
import { BufferWriter } from '../Lib/BufferWriter.js';
import { PacketHeader } from './PacketHeader.js';
import { PacketQuestion } from './PacketQuestion.js';
import { PacketResource } from './PacketResource.js';
import { PacketType } from './PacketType.js';
export declare class Packet {
    header: PacketHeader;
    questions: PacketQuestion[];
    answers: PacketResource[];
    authorities: PacketResource[];
    additionals: PacketResource[];
    constructor(data?: Packet | PacketHeader | null);
    toBuffer(writer?: BufferWriter | null): Buffer;
    static parse(buffer: Buffer): Packet;
    get recursive(): boolean;
    set recursive(yn: boolean);
    toBase64URL(): string;
    static createResponseFromRequest(request: Packet): Packet;
    static createResourceFromQuestion(base: PacketQuestion, record: PacketType, tls?: number): PacketResource;
}
