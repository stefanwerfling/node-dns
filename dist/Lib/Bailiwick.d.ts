import { Packet } from '../Packet/Packet.js';
import { PacketResource } from '../Packet/PacketResource.js';
export declare class Bailiwick {
    static contains(zone: string, name: string): boolean;
    static filter(packet: Packet, zone: string): Packet;
    protected static _inZone(records: PacketResource[], zone: string): PacketResource[];
    protected static _normalize(name: string): string;
}
