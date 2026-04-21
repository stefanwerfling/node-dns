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