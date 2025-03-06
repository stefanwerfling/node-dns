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
            this._buffer.push((d & Math.pow(2, size - i - 1)) ? 1 : 0);
        }
    }

    /**
     * Write buffer to buffer
     * @param {number[]|Buffer} buffer
     */
    public writeBuffer(buffer: number[]|Buffer): void {
        const tBuffer = buffer instanceof Buffer ? [...buffer] : buffer;

        this._buffer = this._buffer.concat(tBuffer);
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