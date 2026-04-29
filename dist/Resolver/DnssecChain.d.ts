import { DnssecVerifyOptions } from '../Lib/Dnssec.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { DNSKEY } from '../Packet/Types/DNSKEY.js';
import { DS } from '../Packet/Types/DS.js';
export type DnssecValidity = 'secure' | 'insecure' | 'bogus' | 'indeterminate';
export type DnssecValidationResult = {
    validity: DnssecValidity;
    reason?: string;
    byKey?: {
        keyTag: number;
        algorithm: number;
    };
};
export declare class DnssecChain {
    static readonly SEP_FLAG: number;
    static readonly ZONE_FLAG: number;
    static validateDnskeyRrset(zone: string, dnskeys: PacketResource[], rrsigs: PacketResource[], parentDs: ReadonlyArray<DS>, options?: DnssecVerifyOptions): DnssecValidationResult;
    static validateRrset(owner: string, rrset: PacketResource[], rrsigs: PacketResource[], dnskeys: PacketResource[], options?: DnssecVerifyOptions): DnssecValidationResult;
    static rrsigsFor(rrsigs: PacketResource[], owner: string, type: number): PacketResource[];
    static groupRrsets(records: PacketResource[]): Map<string, PacketResource[]>;
    static rrsigs(records: PacketResource[]): PacketResource[];
    static dnskeysAt(records: PacketResource[], zone: string): PacketResource[];
    protected static _zoneKeys(dnskeys: PacketResource[]): DNSKEY[];
    protected static _normalize(name: string): string;
}
