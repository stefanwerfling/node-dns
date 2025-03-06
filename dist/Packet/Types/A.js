"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.A = void 0;
const BufferWriter_js_1 = require("../../Lib/BufferWriter.js");
const PacketType_js_1 = require("../PacketType.js");
const PacketTypes_js_1 = require("../PacketTypes.js");
class A extends PacketType_js_1.PacketType {
    address;
    constructor(address = '') {
        super(PacketTypes_js_1.PacketTypes.A);
        this.address = address;
    }
    encode(resource, writer = null) {
        const twriter = writer === null ? new BufferWriter_js_1.BufferWriter() : writer;
        const parts = this.address.split('.');
        twriter.write(parts.length, 16);
        parts.forEach((part) => {
            twriter.write(parseInt(part, 10), 8);
        });
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const parts = [];
        while (length--) {
            parts.push(reader.read(8));
        }
        return new A(parts.join('.'));
    }
}
exports.A = A;
//# sourceMappingURL=A.js.map