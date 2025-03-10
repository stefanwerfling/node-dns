export declare class BufferWriter {
    protected _buffer: number[];
    write(d: number, size: number): void;
    writeBuffer(buffer: number[] | Buffer): void;
    toBuffer(): Buffer;
}
