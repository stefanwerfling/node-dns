import { Buffer } from 'buffer';
export class BufferWriter {
    _buffer = [];
    _nameOffsets = new Map();
    write(d, size) {
        for (let i = 0; i < size; i++) {
            this._buffer.push(d & 2 ** (size - i - 1) ? 1 : 0);
        }
    }
    writeBuffer(buffer) {
        if (buffer instanceof BufferWriter) {
            this._buffer = [...this._buffer, ...buffer._buffer];
        }
        else {
            for (const byte of buffer) {
                this.write(byte, 8);
            }
        }
    }
    getByteOffset() {
        return this._buffer.length / 8;
    }
    getNameOffset(name) {
        return this._nameOffsets.get(name);
    }
    setNameOffset(name, offset) {
        this._nameOffsets.set(name, offset);
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