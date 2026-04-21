import { Buffer } from 'buffer';
export declare class BufferWriter {
    protected _buffer: number[];
    protected _nameOffsets: Map<string, number>;
    write(d: number, size: number): void;
    writeBuffer(buffer: Buffer | BufferWriter): void;
    getByteOffset(): number;
    getNameOffset(name: string): number | undefined;
    setNameOffset(name: string, offset: number): void;
    toBuffer(): Buffer;
}
