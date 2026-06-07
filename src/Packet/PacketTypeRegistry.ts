import {BufferReader} from '../Lib/BufferReader.js';
import {PacketType} from './PacketType.js';
import {PacketTypes} from './PacketTypes.js';
import {A} from './Types/A.js';
import {AAAA} from './Types/AAAA.js';
import {CAA} from './Types/CAA.js';
import {CDNSKEY} from './Types/CDNSKEY.js';
import {CDS} from './Types/CDS.js';
import {CERT} from './Types/CERT.js';
import {CNAME} from './Types/CNAME.js';
import {DNAME} from './Types/DNAME.js';
import {DNSKEY} from './Types/DNSKEY.js';
import {DS} from './Types/DS.js';
import {EDNS} from './Types/EDNS.js';
import {HINFO} from './Types/HINFO.js';
import {HTTPS} from './Types/HTTPS.js';
import {LOC} from './Types/LOC.js';
import {MX} from './Types/MX.js';
import {NAPTR} from './Types/NAPTR.js';
import {NS} from './Types/NS.js';
import {NSEC} from './Types/NSEC.js';
import {NSEC3} from './Types/NSEC3.js';
import {NSEC3PARAM} from './Types/NSEC3PARAM.js';
import {OPENPGPKEY} from './Types/OPENPGPKEY.js';
import {PTR} from './Types/PTR.js';
import {RRSIG} from './Types/RRSIG.js';
import {SMIMEA} from './Types/SMIMEA.js';
import {SOA} from './Types/SOA.js';
import {SPF} from './Types/SPF.js';
import {SRV} from './Types/SRV.js';
import {SSHFP} from './Types/SSHFP.js';
import {SVCB} from './Types/SVCB.js';
import {TLSA} from './Types/TLSA.js';
import {TSIG} from './Types/TSIG.js';
import {TXT} from './Types/TXT.js';
import {URI} from './Types/URI.js';
import {ZONEMD} from './Types/ZONEMD.js';

/**
 * PacketType Registry Type
 */
export type PacketTypeRegistryType = { new(): PacketType;
    decode(reader: BufferReader, length: number): PacketType;
};

/**
 * Packet Type Register
 */
export class PacketTypeRegistry {

    /**
     * Instance of Packet Type Register
     * @private
     */
    private static _instance: PacketTypeRegistry|null = null;

    /**
     * Return the Instance from Packet type register
     * @return {PacketTypeRegistry}
     */
    public static getInstance(): PacketTypeRegistry {
        if (PacketTypeRegistry._instance === null) {
            PacketTypeRegistry._instance = new PacketTypeRegistry();

            // register default packets
            PacketTypeRegistry._instance.registerPacket(PacketTypes.A, A);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.MX, MX);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.AAAA, AAAA);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.NS, NS);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.CNAME, CNAME);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.DNAME, DNAME);
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
            PacketTypeRegistry._instance.registerPacket(PacketTypes.NSEC3PARAM, NSEC3PARAM);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.CDS, CDS);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.CDNSKEY, CDNSKEY);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.TLSA, TLSA);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.SVCB, SVCB);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.HTTPS, HTTPS);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.TSIG, TSIG);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.CAA, CAA);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.HINFO, HINFO);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.URI, URI);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.ZONEMD, ZONEMD);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.OPENPGPKEY, OPENPGPKEY);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.SMIMEA, SMIMEA);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.CERT, CERT);
            PacketTypeRegistry._instance.registerPacket(PacketTypes.LOC, LOC);
        }

        return PacketTypeRegistry._instance;
    }

    /**
     * Map with all registered packets
     * @private
     */
    private _packetMap: Map<number, PacketTypeRegistryType> = new Map();

    /**
     * register a packet
     * @param {PacketTypes|number} type
     * @param {PacketTypeRegistryType} packetType
     */
    public registerPacket(type: PacketTypes|number, packetType: PacketTypeRegistryType): void {
        this._packetMap.set(type, packetType);
    }

    /**
     * Return PacketType class
     * @param {PacketTypes|number} type
     * @return {PacketTypeRegistryType|null}
     */
    public getPacketType(type: PacketTypes|number): PacketTypeRegistryType|null {
        return this._packetMap.get(type) || null;
    }

    /**
     * Create a new packet instance
     * @param {PacketTypes|number} type
     * @return {PacketType|null}
     */
    public createPacket(type: PacketTypes|number): PacketType|null {
        const packetType = this._packetMap.get(type);

        if (packetType) {
            return new packetType();
        }

        return null;
    }

}