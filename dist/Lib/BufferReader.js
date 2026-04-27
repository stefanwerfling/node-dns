export class BufferReader {
    _buffer;
    _offset = 0;
    constructor(buffer, offset = 0) {
        this._buffer = buffer;
        this._offset = offset || 0;
    }
    static read(buffer, offset, length) {
        const byteOffset = offset >> 3;
        const bitInByte = offset & 7;
        if (bitInByte === 0) {
            if (length === 8) {
                return buffer.readUInt8(byteOffset);
            }
            if (length === 16) {
                return buffer.readUInt16BE(byteOffset);
            }
            if (length === 32) {
                return buffer.readUInt32BE(byteOffset);
            }
        }
        let value = 0;
        let bitsNeeded = length;
        let curByte = byteOffset;
        let curBitInByte = bitInByte;
        while (bitsNeeded > 0) {
            const bitsInThisByte = 8 - curBitInByte;
            const take = bitsInThisByte < bitsNeeded ? bitsInThisByte : bitsNeeded;
            const shift = bitsInThisByte - take;
            const mask = (1 << take) - 1;
            const bits = (buffer[curByte] >> shift) & mask;
            value = (value << take) | bits;
            bitsNeeded -= take;
            curBitInByte += take;
            if (curBitInByte === 8) {
                curBitInByte = 0;
                curByte++;
            }
        }
        return value;
    }
    read(size) {
        const val = BufferReader.read(this._buffer, this._offset, size);
        this._offset += size;
        return val;
    }
    getOffset() {
        return this._offset;
    }
    setOffset(offset) {
        this._offset = offset;
    }
}
//# sourceMappingURL=BufferReader.js.map