import { Buffer } from 'buffer';
export declare class BufferWriter {
    protected _buffer: number[];
    write(d: number, size: number): void;
    writeBuffer(buffer: Buffer | BufferWriter): void;
    toBuffer(): Buffer;
}
