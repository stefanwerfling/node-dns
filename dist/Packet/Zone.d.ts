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
    toAxfrPackets(query: Packet): Packet[];
    soaRdata(): SOA;
}
