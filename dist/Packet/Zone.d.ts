import { ZoneParseOptions } from '../Lib/ZoneParser.js';
import { Packet } from './Packet.js';
import { PacketResource } from './PacketResource.js';
import { PacketTypes } from './PacketTypes.js';
import { SOA } from './Types/SOA.js';
export declare class Zone {
    origin: string;
    records: PacketResource[];
    constructor(origin: string, records?: PacketResource[]);
    static fromZoneFile(text: string, options?: ZoneParseOptions): Zone;
    soa(): PacketResource;
    recordsOfType(type: PacketTypes): IterableIterator<PacketResource>;
    static readonly AXFR_MAX_MESSAGE_SIZE: number;
    toAxfrPackets(query: Packet, options?: {
        maxMessageSize?: number;
    }): Packet[];
    protected static _buildAxfrResponse(query: Packet): Packet;
    soaRdata(): SOA;
    toIxfrPackets(query: Packet, options?: {
        history?: ZoneChangeSet[];
    }): Packet[];
    protected static _extractClientSerial(query: Packet): number | null;
    protected static _stitchChain(history: ZoneChangeSet[], from: number, to: number): ZoneChangeSet[] | null;
}
export type ZoneChangeSet = {
    fromSerial: number;
    toSerial: number;
    fromSoa: PacketResource;
    toSoa: PacketResource;
    deletions: PacketResource[];
    additions: PacketResource[];
};
