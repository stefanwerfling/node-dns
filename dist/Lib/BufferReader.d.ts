export declare class BufferReader {
    protected _buffer: Buffer;
    protected _offset: number;
    constructor(buffer: Buffer, offset?: number);
    static read(buffer: Buffer, offset: number, length: number): number;
    read(size: number): number;
    getOffset(): number;
    setOffset(offset: number): void;
}
