"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CAA = void 0;
const BufferWriter_js_1 = require("../../Lib/BufferWriter.js");
const PacketType_js_1 = require("../PacketType.js");
const PacketTypes_js_1 = require("../PacketTypes.js");
class CAA extends PacketType_js_1.PacketType {
    flags;
    tag;
    value;
    constructor(flags = 0, tag = '', value = '') {
        super(PacketTypes_js_1.PacketTypes.CAA);
        this.flags = flags;
        this.tag = tag;
        this.value = value;
    }
    encode(resource, writer = null) {
        const twriter = writer === null ? new BufferWriter_js_1.BufferWriter() : writer;
        const buffer = Buffer.from(this.tag + this.value, 'utf8');
        twriter.write(2 + buffer.length, 16);
        twriter.write(this.flags, 8);
        twriter.write(this.tag.length, 8);
        buffer.forEach((c) => {
            twriter.write(c, 8);
        });
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const flags = reader.read(8);
        const tagLen = reader.read(8);
        const bufferTag = Buffer.alloc(tagLen);
        for (let i = 0; i < tagLen; i++) {
            bufferTag[i] = reader.read(8);
        }
        const tag = bufferTag.toString('utf8');
        const valueLen = length - 2 - tagLen;
        const bufferValue = Buffer.alloc(valueLen);
        for (let i = 0; i < valueLen; i++) {
            bufferValue[i] = reader.read(8);
        }
        const value = bufferValue.toString('utf8');
        return new CAA(flags, tag, value);
    }
}
exports.CAA = CAA;
//# sourceMappingURL=CAA.js.map