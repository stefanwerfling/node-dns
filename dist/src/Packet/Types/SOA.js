"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SOA = void 0;
const BufferWriter_js_1 = require("../../Lib/BufferWriter.js");
const PacketName_js_1 = require("../PacketName.js");
const PacketType_js_1 = require("../PacketType.js");
const PacketTypes_js_1 = require("../PacketTypes.js");
class SOA extends PacketType_js_1.PacketType {
    primary;
    admin;
    serial;
    refresh;
    retry;
    expiration;
    minimum;
    constructor(primary = '', admin = '', serial = 0, refresh = 0, retry = 0, expiration = 0, minimum = 0) {
        super(PacketTypes_js_1.PacketTypes.SOA);
        this.primary = primary;
        this.admin = admin;
        this.serial = serial;
        this.refresh = refresh;
        this.retry = retry;
        this.expiration = expiration;
        this.minimum = minimum;
    }
    encode(resource, writer = null) {
        const twriter = writer === null ? new BufferWriter_js_1.BufferWriter() : writer;
        const namePrimary = PacketName_js_1.PacketName.encode(this.primary);
        const nameAdmin = PacketName_js_1.PacketName.encode(this.admin);
        twriter.write(namePrimary.length + nameAdmin.length + ((32 * 5) / 8), 16);
        twriter.writeBuffer(namePrimary);
        twriter.writeBuffer(nameAdmin);
        twriter.write(this.serial, 32);
        twriter.write(this.refresh, 32);
        twriter.write(this.retry, 32);
        twriter.write(this.expiration, 32);
        twriter.write(this.minimum, 32);
        return twriter.toBuffer();
    }
    static decode(reader) {
        const soa = new SOA();
        soa.primary = PacketName_js_1.PacketName.decode(reader);
        soa.admin = PacketName_js_1.PacketName.decode(reader);
        soa.serial = reader.read(32);
        soa.refresh = reader.read(32);
        soa.retry = reader.read(32);
        soa.expiration = reader.read(32);
        soa.minimum = reader.read(32);
        return soa;
    }
}
exports.SOA = SOA;
//# sourceMappingURL=SOA.js.map