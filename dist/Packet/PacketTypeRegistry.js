import { PacketTypes } from './PacketTypes.js';
import { A } from './Types/A.js';
import { AAAA } from './Types/AAAA.js';
import { CAA } from './Types/CAA.js';
import { CNAME } from './Types/CNAME.js';
import { DNSKEY } from './Types/DNSKEY.js';
import { DS } from './Types/DS.js';
import { EDNS } from './Types/EDNS.js';
import { HTTPS } from './Types/HTTPS.js';
import { MX } from './Types/MX.js';
import { NAPTR } from './Types/NAPTR.js';
import { NS } from './Types/NS.js';
import { NSEC } from './Types/NSEC.js';
import { NSEC3 } from './Types/NSEC3.js';
import { PTR } from './Types/PTR.js';
import { RRSIG } from './Types/RRSIG.js';
import { SOA } from './Types/SOA.js';
import { SPF } from './Types/SPF.js';
import { SRV } from './Types/SRV.js';
import { SSHFP } from './Types/SSHFP.js';
import { SVCB } from './Types/SVCB.js';
import { TLSA } from './Types/TLSA.js';
import { TSIG } from './Types/TSIG.js';
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
            PacketTypeRegistry._instance.registerPacket(PacketTypes.NAPTR, NAPTR);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.EDNS, EDNS);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.DS, DS);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.SSHFP, SSHFP);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.RRSIG, RRSIG);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.NSEC, NSEC);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.DNSKEY, DNSKEY);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.NSEC3, NSEC3);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.TLSA, TLSA);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.SVCB, SVCB);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.HTTPS, HTTPS);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.TSIG, TSIG);
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