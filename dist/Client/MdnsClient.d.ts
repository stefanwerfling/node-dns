import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
export declare const MDNS_MULTICAST_IPV4: '224.0.0.251';
export declare const MDNS_MULTICAST_IPV6: 'ff02::fb';
export declare const MDNS_PORT: 5353;
export declare const MDNS_QU_BIT: 0x8000;
export declare const MDNS_CACHE_FLUSH_BIT: 0x8000;
export type MdnsClientOptions = {
    multicastAddr?: string;
    port?: number;
    timeoutMs?: number;
    family?: 'udp4' | 'udp6';
    unicastResponse?: boolean;
    interfaceAddress?: string;
    joinMulticastGroup?: boolean;
};
export type MdnsResponse = {
    packet: Packet;
    answers: PacketResource[];
    additionals: PacketResource[];
    sender: {
        address: string;
        port: number;
    };
};
export declare class MdnsClient {
    static makeQuery(name: string, type: PacketTypes | number, cls?: PacketClass | number, unicastResponse?: boolean): Packet;
    static request(options?: MdnsClientOptions): (name: string, type: PacketTypes | number, cls?: PacketClass | number) => Promise<MdnsResponse[]>;
    protected static _isMulticast(addr: string): boolean;
}
