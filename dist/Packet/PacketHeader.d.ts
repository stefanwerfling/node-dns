import { Buffer } from 'buffer';
import { BufferReader } from '../Lib/BufferReader.js';
import { BufferWriter } from '../Lib/BufferWriter.js';
export declare class PacketHeader {
    id: number;
    qr: number;
    opcode: number;
    aa: number;
    tc: number;
    rd: number;
    ra: number;
    z: number;
    rcode: number;
    qdcount: number;
    ancount: number;
    nscount: number;
    arcount: number;
    static parse(reader: BufferReader | Buffer): PacketHeader;
    toBuffer(writer?: BufferWriter | null): Buffer;
}
