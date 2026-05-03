import { Buffer } from 'buffer';
import { PacketResource } from '../Packet/PacketResource.js';
export type MdnsProbeResult = {
    result: 'claimed' | 'conflict';
    conflictRecord?: PacketResource;
    conflictSource?: {
        address: string;
        port: number;
    };
};
export type MdnsProbeOptions = {
    records: PacketResource[];
    multicastAddr?: string;
    port?: number;
    family?: 'udp4' | 'udp6';
    interfaceAddress?: string;
    bindPort?: number;
    joinMulticastGroup?: boolean;
    initialJitterMs?: number;
    probeIntervalMs?: number;
    probeAttempts?: number;
    announceAttempts?: number;
    announceIntervalMs?: number;
    random?: () => number;
};
export declare class MdnsProbe {
    static claim(options: MdnsProbeOptions): Promise<MdnsProbeResult>;
    static canonicalRecordKey(record: PacketResource): Buffer;
    static compareRecordSets(a: PacketResource[], b: PacketResource[]): number;
    private static _resolveOptions;
    private static _run;
    private static _classify;
    private static _sendProbe;
    private static _sendAnnouncement;
    private static _sendPacket;
    private static _nameEquals;
    private static _normalizeName;
    private static _keyInSet;
    private static _isMulticast;
}
