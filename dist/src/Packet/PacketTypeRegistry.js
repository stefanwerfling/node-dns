"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PacketTypeRegistry = void 0;
const PacketTypes_js_1 = require("./PacketTypes.js");
const A_js_1 = require("./Types/A.js");
const AAAA_js_1 = require("./Types/AAAA.js");
const CAA_js_1 = require("./Types/CAA.js");
const CNAME_js_1 = require("./Types/CNAME.js");
const MX_js_1 = require("./Types/MX.js");
const NS_js_1 = require("./Types/NS.js");
const PTR_js_1 = require("./Types/PTR.js");
const SOA_js_1 = require("./Types/SOA.js");
const SPF_js_1 = require("./Types/SPF.js");
const SRV_js_1 = require("./Types/SRV.js");
const TXT_js_1 = require("./Types/TXT.js");
class PacketTypeRegistry {
    static _instance = null;
    static getInstance() {
        if (PacketTypeRegistry._instance === null) {
            PacketTypeRegistry._instance = new PacketTypeRegistry();
            PacketTypeRegistry._instance.registerPacket(PacketTypes_js_1.PacketTypes.A, A_js_1.A);
            PacketTypeRegistry._instance.registerPacket(PacketTypes_js_1.PacketTypes.MX, MX_js_1.MX);
            PacketTypeRegistry._instance.registerPacket(PacketTypes_js_1.PacketTypes.AAAA, AAAA_js_1.AAAA);
            PacketTypeRegistry._instance.registerPacket(PacketTypes_js_1.PacketTypes.NS, NS_js_1.NS);
            PacketTypeRegistry._instance.registerPacket(PacketTypes_js_1.PacketTypes.CNAME, CNAME_js_1.CNAME);
            PacketTypeRegistry._instance.registerPacket(PacketTypes_js_1.PacketTypes.PTR, PTR_js_1.PTR);
            PacketTypeRegistry._instance.registerPacket(PacketTypes_js_1.PacketTypes.TXT, TXT_js_1.TXT);
            PacketTypeRegistry._instance.registerPacket(PacketTypes_js_1.PacketTypes.SPF, SPF_js_1.SPF);
            PacketTypeRegistry._instance.registerPacket(PacketTypes_js_1.PacketTypes.SOA, SOA_js_1.SOA);
            PacketTypeRegistry._instance.registerPacket(PacketTypes_js_1.PacketTypes.SRV, SRV_js_1.SRV);
            PacketTypeRegistry._instance.registerPacket(PacketTypes_js_1.PacketTypes.CAA, CAA_js_1.CAA);
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