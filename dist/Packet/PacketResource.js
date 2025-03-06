"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PacketResource = void 0;
const tslib_1 = require("tslib");
const util = tslib_1.__importStar(require("node:util"));
const BufferReader_js_1 = require("../Lib/BufferReader.js");
const BufferWriter_js_1 = require("../Lib/BufferWriter.js");
const PacketClass_js_1 = require("./PacketClass.js");
const PacketName_js_1 = require("./PacketName.js");
const PacketTypeRegistry_js_1 = require("./PacketTypeRegistry.js");
class PacketResource {
    name;
    packetType;
    class;
    ttl;
    constructor(name, packetType, cls = PacketClass_js_1.PacketClass.ANY, ttl = 300) {
        this.name = name;
        this.packetType = packetType;
        this.class = cls;
        this.ttl = ttl;
    }
    toBuffer(writer = null) {
        return PacketResource.encode(this, writer);
    }
    static encode(resource, writer = null) {
        const twriter = writer === null ? new BufferWriter_js_1.BufferWriter() : writer;
        PacketName_js_1.PacketName.encode(resource.name, twriter);
        twriter.write(resource.packetType.type, 16);
        twriter.write(resource.class, 16);
        twriter.write(resource.ttl, 32);
        return resource.packetType.encode(resource, twriter);
    }
    static decode(reader) {
        const treader = reader instanceof Buffer ? new BufferReader_js_1.BufferReader(reader) : reader;
        const name = PacketName_js_1.PacketName.decode(treader);
        const type = treader.read(16);
        const cls = treader.read(16);
        const ttl = treader.read(32);
        const len = treader.read(16);
        const packetType = PacketTypeRegistry_js_1.PacketTypeRegistry.getInstance().getPacketType(type);
        if (packetType === null) {
            throw new Error(util.format('node-dns > unknown parser type: %d by domain: %s', type, name));
        }
        const packet = packetType.decode(treader, len);
        return new PacketResource(name, packet, cls, ttl);
    }
}
exports.PacketResource = PacketResource;
//# sourceMappingURL=PacketResource.js.map