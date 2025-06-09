import { Buffer } from 'buffer';
export class BufferWriter {
    _buffer = [];
    write(d, size) {
        for (let i = 0; i < size; i++) {
            this._buffer.push(d & 2 ** (size - i - 1) ? 1 : 0);
        }
    }
    writeBuffer(buffer) {
        const tBuffer = buffer instanceof Buffer ? [...buffer] : buffer;
        this._buffer = [...this._buffer, ...tBuffer];
    }
    toBuffer() {
        const arr = [];
        for (let i = 0; i < this._buffer.length; i += 8) {
            const chunk = this._buffer.slice(i, i + 8);
            arr.push(parseInt(chunk.join(''), 2));
        }
        return Buffer.from(arr);
    }
}
//# sourceMappingURL=BufferWriter.js.map