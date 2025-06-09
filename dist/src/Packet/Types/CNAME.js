"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CNAME = void 0;
const BufferWriter_js_1 = require("../../Lib/BufferWriter.js");
const PacketName_js_1 = require("../PacketName.js");
const PacketType_js_1 = require("../PacketType.js");
const PacketTypes_js_1 = require("../PacketTypes.js");
class CNAME extends PacketType_js_1.PacketType {
    domain;
    constructor(domain = '') {
        super(PacketTypes_js_1.PacketTypes.CNAME);
        this.domain = domain;
    }
    encode(resource, writer = null) {
        const twriter = writer === null ? new BufferWriter_js_1.BufferWriter() : writer;
        const buffer = PacketName_js_1.PacketName.encode(this.domain);
        twriter.write(buffer.length, 16);
        twriter.writeBuffer(buffer);
        return twriter.toBuffer();
    }
    static decode(reader) {
        const ns = PacketName_js_1.PacketName.decode(reader);
        return new CNAME(ns);
    }
}
exports.CNAME = CNAME;
//# sourceMappingURL=CNAME.js.map