import { Buffer } from 'buffer';

/**
 * Buffer Writer
 */
export class BufferWriter {

    /**
     * Buffer
     * @protected
     */
    protected _buffer: number[] = [];

    /**
     * Tracks byte offsets of previously written domain name suffixes
     * for DNS name compression (RFC 1035 Section 4.1.4).
     * @protected
     */
    protected _nameOffsets: Map<string, number> = new Map();

    /**
     * Write to the buffer
     * @param {number} d
     * @param {number} size
     */
    public write(d: number, size: number): void {
        for (let i = 0; i < size; i++) {
            // eslint-disable-next-line no-bitwise
            this._buffer.push(d & 2**(size - i - 1) ? 1 : 0);
        }
    }

    /**
     * Write buffer to buffer
     * @param {Buffer|BufferWriter} buffer
     */
    public writeBuffer(buffer: Buffer|BufferWriter): void {
        if (buffer instanceof BufferWriter) {
            this._buffer = [...this._buffer, ...buffer._buffer];
        } else {
            for (const byte of buffer) {
                this.write(byte, 8);
            }
        }
    }

    /**
     * Return the current byte offset in the buffer
     * @return {number}
     */
    public getByteOffset(): number {
        return this._buffer.length / 8;
    }

    /**
     * Return the byte offset of a previously written domain name suffix
     * @param {string} name
     * @return {number|undefined}
     */
    public getNameOffset(name: string): number|undefined {
        return this._nameOffsets.get(name);
    }

    /**
     * Register a domain name suffix at a byte offset for compression
     * @param {string} name
     * @param {number} offset
     */
    public setNameOffset(name: string, offset: number): void {
        this._nameOffsets.set(name, offset);
    }

    /**
     * Convert Buffer to Buffer object
     * @return {Buffer}
     */
    public toBuffer(): Buffer {
        const arr: number[] = [];

        for (let i = 0; i < this._buffer.length; i += 8) {
            const chunk = this._buffer.slice(i, i + 8);
            arr.push(parseInt(chunk.join(''), 2));
        }

        return Buffer.from(arr);
    }

}