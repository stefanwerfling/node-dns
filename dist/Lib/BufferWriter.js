import { Buffer } from 'buffer';
export class BufferWriter {
    _bytes = [];
    _bitLength = 0;
    _nameOffsets = new Map();
    write(d, size) {
        const bitInByte = this._bitLength & 7;
        if (bitInByte === 0) {
            if (size === 8) {
                this._bytes.push(d & 0xFF);
                this._bitLength += 8;
                return;
            }
            if (size === 16) {
                this._bytes.push((d >>> 8) & 0xFF, d & 0xFF);
                this._bitLength += 16;
                return;
            }
            if (size === 32) {
                this._bytes.push((d >>> 24) & 0xFF, (d >>> 16) & 0xFF, (d >>> 8) & 0xFF, d & 0xFF);
                this._bitLength += 32;
                return;
            }
        }
        let bitsLeft = size;
        while (bitsLeft > 0) {
            const byteOffset = this._bitLength >> 3;
            const curBitInByte = this._bitLength & 7;
            const room = 8 - curBitInByte;
            const take = room < bitsLeft ? room : bitsLeft;
            const shiftSrc = bitsLeft - take;
            const shiftDst = room - take;
            const bits = (d >>> shiftSrc) & ((1 << take) - 1);
            if (this._bytes.length <= byteOffset) {
                this._bytes.push(0);
            }
            this._bytes[byteOffset] |= bits << shiftDst;
            bitsLeft -= take;
            this._bitLength += take;
        }
    }
    writeBuffer(buffer) {
        const aligned = (this._bitLength & 7) === 0;
        if (buffer instanceof BufferWriter) {
            const otherBytes = buffer._bytes;
            const otherBitLength = buffer._bitLength;
            const otherFullBytes = otherBitLength >> 3;
            const otherRemainderBits = otherBitLength - otherFullBytes * 8;
            if (aligned) {
                for (let i = 0; i < otherFullBytes; i++) {
                    this._bytes.push(otherBytes[i]);
                }
                this._bitLength += otherFullBytes * 8;
            }
            else {
                for (let i = 0; i < otherFullBytes; i++) {
                    this.write(otherBytes[i], 8);
                }
            }
            if (otherRemainderBits > 0) {
                const tail = (otherBytes[otherFullBytes] >>> (8 - otherRemainderBits))
                    & ((1 << otherRemainderBits) - 1);
                this.write(tail, otherRemainderBits);
            }
            return;
        }
        if (aligned) {
            for (let i = 0; i < buffer.length; i++) {
                this._bytes.push(buffer[i]);
            }
            this._bitLength += buffer.length * 8;
            return;
        }
        for (let i = 0; i < buffer.length; i++) {
            this.write(buffer[i], 8);
        }
    }
    getByteOffset() {
        return this._bitLength >> 3;
    }
    getNameOffset(name) {
        return this._nameOffsets.get(name);
    }
    setNameOffset(name, offset) {
        this._nameOffsets.set(name, offset);
    }
    toBuffer() {
        return Buffer.from(this._bytes);
    }
}
//# sourceMappingURL=BufferWriter.js.map