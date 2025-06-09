"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BufferReader = void 0;
class BufferReader {
    _buffer;
    _offset = 0;
    constructor(buffer, offset = 0) {
        this._buffer = buffer;
        this._offset = offset || 0;
    }
    static read(buffer, offset, length) {
        let a = [];
        let c = Math.ceil(length / 8);
        let l = Math.floor(offset / 8);
        const m = offset % 8;
        const t = (n) => {
            const r = [0, 0, 0, 0, 0, 0, 0, 0];
            for (let i = 7; i >= 0; i--) {
                if (n & Math.pow(2, i)) {
                    r[7 - i] = 1;
                }
                else {
                    r[7 - i] = 0;
                }
            }
            a = a.concat(r);
        };
        const p = (ta) => {
            let n = 0;
            const f = ta.length - 1;
            for (let i = f; i >= 0; i--) {
                if (ta[f - i]) {
                    n += 2 ** i;
                }
            }
            return n;
        };
        while (c--) {
            t(buffer.readUInt8(l++));
        }
        return p(a.slice(m, m + length));
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
exports.BufferReader = BufferReader;
//# sourceMappingURL=BufferReader.js.map