import { BufferReader } from '../Lib/BufferReader.js';
import { PacketType } from './PacketType.js';
import { PacketTypes } from './PacketTypes.js';
export type PacketTypeRegistryType = {
    new (): PacketType;
    decode(reader: BufferReader, length: number): PacketType;
};
export declare class PacketTypeRegistry {
    private static _instance;
    static getInstance(): PacketTypeRegistry;
    private _packetMap;
    registerPacket(type: PacketTypes | number, packetType: PacketTypeRegistryType): void;
    getPacketType(type: PacketTypes | number): PacketTypeRegistryType | null;
    createPacket(type: PacketTypes | number): PacketType | null;
}
