import { BufferWriter } from '../Lib/BufferWriter.js';
import { PacketHeader } from './PacketHeader.js';
import { PacketQuestion } from './PacketQuestion.js';
import { PacketResource } from './PacketResource.js';
export declare class Packet {
    header: PacketHeader;
    questions: PacketQuestion[];
    answers: PacketResource[];
    authorities: PacketResource[];
    additionals: PacketResource[];
    constructor(data?: Packet | PacketHeader | null);
    toBuffer(writer?: BufferWriter | null): Buffer;
    static parse(buffer: Buffer): Packet;
}
