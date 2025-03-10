"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SRV = void 0;
const BufferWriter_js_1 = require("../../Lib/BufferWriter.js");
const PacketName_js_1 = require("../PacketName.js");
const PacketType_js_1 = require("../PacketType.js");
const PacketTypes_js_1 = require("../PacketTypes.js");
class SRV extends PacketType_js_1.PacketType {
    priority;
    weight;
    port;
    target;
    constructor(priority = 0, weight = 0, port = 0, target = '') {
        super(PacketTypes_js_1.PacketTypes.SRV);
        this.priority = priority;
        this.weight = weight;
        this.port = port;
        this.target = target;
    }
    encode(resource, writer = null) {
        const twriter = writer === null ? new BufferWriter_js_1.BufferWriter() : writer;
        const targetBuffer = PacketName_js_1.PacketName.encode(this.target);
        twriter.write(targetBuffer.length + 6, 16);
        twriter.write(this.priority, 16);
        twriter.write(this.weight, 16);
        twriter.write(this.port, 16);
        twriter.writeBuffer(targetBuffer);
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const priority = reader.read(16);
        const weight = reader.read(16);
        const port = reader.read(16);
        const target = PacketName_js_1.PacketName.decode(reader);
        return new SRV(priority, weight, port, target);
    }
}
exports.SRV = SRV;
//# sourceMappingURL=SRV.js.map