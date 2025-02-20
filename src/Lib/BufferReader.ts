/**
 * Buffer Reader
 */
export class BufferReader {

    /**
     * Buffer
     * @protected
     */
    protected _buffer: Buffer;

    /**
     * Buffer offset
     * @protected
     */
    protected _offset: number = 0;

    /**
     * Constructor
     * @param {Buffer} buffer
     * @param {number} offset
     */
    public constructor(buffer: Buffer, offset: number) {
        this._buffer = buffer;
        this._offset = offset || 0;
    }

    /**
     * Static Read
     * @param {Buffer} buffer
     * @param {number} offset
     * @param {number} length
     * @return {number}
     */
    public static read(buffer: Buffer, offset: number, length: number): number {
        let a: number[] = [];
        let c = Math.ceil(length / 8);
        let l = Math.floor(offset / 8);
        const m = offset % 8;

        const t = (n: number): void => {
            const r = [ 0, 0, 0, 0, 0, 0, 0, 0 ];

            for (let i = 7; i >= 0; i--) {
                r[7 - i] = n & Math.pow(2, i) ? 1 : 0;
            }

            a = a.concat(r);
        };

        const p = (a: number[]): number => {
            let n = 0;
            const f = a.length - 1;

            for (let i = f; i >= 0; i--) {
                if (a[f - i]) n += Math.pow(2, i);
            }

            return n;
        };

        while (c--) {
            t(buffer.readUInt8(l++));
        }

        return p(a.slice(m, m + length));
    }

    /**
     * read
     * @param {number} size
     * @return {number}
     */
    public read(size: number): number {
        const val = BufferReader.read(this._buffer, this._offset, size);
        this._offset += size;
        return val;
    }
}