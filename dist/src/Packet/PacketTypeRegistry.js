"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PacketTypeRegistry = void 0;
const PacketTypes_js_1 = require("./PacketTypes.js");
const A_js_1 = require("./Types/A.js");
const AAAA_js_1 = require("./Types/AAAA.js");
const MX_js_1 = require("./Types/MX.js");
const NS_js_1 = require("./Types/NS.js");
const SRV_js_1 = require("./Types/SRV.js");
class PacketTypeRegistry {
    static _instance = null;
    static getInstance() {
        if (PacketTypeRegistry._instance === null) {
            PacketTypeRegistry._instance = new PacketTypeRegistry();
            PacketTypeRegistry._instance.registerPacket(PacketTypes_js_1.PacketTypes.A, A_js_1.A);
            PacketTypeRegistry._instance.registerPacket(PacketTypes_js_1.PacketTypes.MX, MX_js_1.MX);
            PacketTypeRegistry._instance.registerPacket(PacketTypes_js_1.PacketTypes.AAAA, AAAA_js_1.AAAA);
            PacketTypeRegistry._instance.registerPacket(PacketTypes_js_1.PacketTypes.NS, NS_js_1.NS);
            PacketTypeRegistry._instance.registerPacket(PacketTypes_js_1.PacketTypes.SRV, SRV_js_1.SRV);
        }
        return PacketTypeRegistry._instance;
    }
    _packetMap = new Map();
    registerPacket(type, packetType) {
        this._packetMap.set(type, packetType);
    }
    getPacketType(type) {
        return this._packetMap.get(type) || null;
    }
    createPacket(type) {
        const packetType = this._packetMap.get(type);
        if (packetType) {
            return new packetType();
        }
        return null;
    }
}
exports.PacketTypeRegistry = PacketTypeRegistry;
//# sourceMappingURL=PacketTypeRegistry.js.map