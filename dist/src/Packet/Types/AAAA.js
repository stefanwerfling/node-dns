"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AAAA = void 0;
const BufferWriter_js_1 = require("../../Lib/BufferWriter.js");
const IP_js_1 = require("../IP.js");
const PacketType_js_1 = require("../PacketType.js");
const PacketTypes_js_1 = require("../PacketTypes.js");
class AAAA extends PacketType_js_1.PacketType {
    address;
    constructor(address = '') {
        super(PacketTypes_js_1.PacketTypes.AAAA);
        this.address = address;
    }
    encode(resource, writer = null) {
        const twriter = writer === null ? new BufferWriter_js_1.BufferWriter() : writer;
        const parts = IP_js_1.IP.fromIPv6(this.address);
        twriter.write(parts.length * 2, 16);
        parts.forEach((part) => {
            twriter.write(parseInt(`${part}`, 16), 16);
        });
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const parts = [];
        let tlength = length;
        while (tlength) {
            tlength -= 2;
            parts.push(reader.read(16));
        }
        const address = IP_js_1.IP.toIPv6(parts);
        return new AAAA(address);
    }
}
exports.AAAA = AAAA;
//# sourceMappingURL=AAAA.js.map