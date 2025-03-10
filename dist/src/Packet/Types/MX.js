"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MX = void 0;
const BufferWriter_js_1 = require("../../Lib/BufferWriter.js");
const PacketName_js_1 = require("../PacketName.js");
const PacketType_js_1 = require("../PacketType.js");
const PacketTypes_js_1 = require("../PacketTypes.js");
class MX extends PacketType_js_1.PacketType {
    exchange;
    priority;
    constructor(exchange = '', priority = 0) {
        super(PacketTypes_js_1.PacketTypes.MX);
        this.exchange = exchange;
        this.priority = priority;
    }
    encode(resource, writer = null) {
        const twriter = writer === null ? new BufferWriter_js_1.BufferWriter() : writer;
        const buffer = PacketName_js_1.PacketName.encode(this.exchange, null);
        twriter.write(buffer.length + 2, 16);
        twriter.write(this.priority, 16);
        twriter.writeBuffer(buffer);
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const priority = reader.read(16);
        const exchange = PacketName_js_1.PacketName.decode(reader);
        return new MX(exchange, priority);
    }
}
exports.MX = MX;
//# sourceMappingURL=MX.js.map