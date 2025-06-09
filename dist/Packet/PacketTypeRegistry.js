import { PacketTypes } from './PacketTypes.js';
import { A } from './Types/A.js';
import { AAAA } from './Types/AAAA.js';
import { CAA } from './Types/CAA.js';
import { CNAME } from './Types/CNAME.js';
import { MX } from './Types/MX.js';
import { NS } from './Types/NS.js';
import { PTR } from './Types/PTR.js';
import { SOA } from './Types/SOA.js';
import { SPF } from './Types/SPF.js';
import { SRV } from './Types/SRV.js';
import { TXT } from './Types/TXT.js';
export class PacketTypeRegistry {
    static _instance = null;
    static getInstance() {
        if (PacketTypeRegistry._instance === null) {
            PacketTypeRegistry._instance = new PacketTypeRegistry();
            PacketTypeRegistry._instance.registerPacket(PacketTypes.A, A);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.MX, MX);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.AAAA, AAAA);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.NS, NS);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.CNAME, CNAME);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.PTR, PTR);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.TXT, TXT);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.SPF, SPF);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.SOA, SOA);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.SRV, SRV);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.CAA, CAA);
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
//# sourceMappingURL=PacketTypeRegistry.js.map