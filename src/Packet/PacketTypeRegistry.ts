import {BufferReader} from '../Lib/BufferReader.js';
import {PacketType} from './PacketType.js';
import {PacketTypes} from './PacketTypes.js';
import {A} from './Types/A.js';
import {AAAA} from './Types/AAAA.js';
import {MX} from './Types/MX.js';
import {NS} from './Types/NS.js';
import {SRV} from './Types/SRV.js';

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
            PacketTypeRegistry._instance.registerPacket(PacketTypes.SRV, SRV);
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