import { BufferReader } from '../Lib/BufferReader.js';
import { BufferWriter } from '../Lib/BufferWriter.js';
export declare class PacketName {
    static COPY: number;
    static decode(reader: BufferReader | Buffer): string;
    static encode(domain: string, writer?: BufferWriter | null): Buffer;
}
