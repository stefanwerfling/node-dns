"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NS = void 0;
const BufferWriter_js_1 = require("../../Lib/BufferWriter.js");
const PacketName_js_1 = require("../PacketName.js");
const PacketType_js_1 = require("../PacketType.js");
const PacketTypes_js_1 = require("../PacketTypes.js");
class NS extends PacketType_js_1.PacketType {
    ns;
    constructor(ns = '') {
        super(PacketTypes_js_1.PacketTypes.NS);
        this.ns = ns;
    }
    encode(resource, writer = null) {
        const twriter = writer === null ? new BufferWriter_js_1.BufferWriter() : writer;
        const buffer = PacketName_js_1.PacketName.encode(this.ns);
        twriter.write(buffer.length, 16);
        twriter.writeBuffer(buffer);
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const ns = PacketName_js_1.PacketName.decode(reader);
        return new NS(ns);
    }
}
exports.NS = NS;
//# sourceMappingURL=NS.js.map