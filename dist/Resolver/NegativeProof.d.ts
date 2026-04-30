import { Buffer } from 'buffer';
import { PacketResource } from '../Packet/PacketResource.js';
export declare class NegativeProof {
    static verifyNxdomainNsec(qname: string, zone: string, records: PacketResource[]): boolean;
    static verifyNodataNsec(qname: string, qtype: number, records: PacketResource[]): boolean;
    static closestEncloserNsec(qname: string, zone: string, nsecs: PacketResource[]): string | null;
    static verifyNxdomainNsec3(qname: string, zone: string, records: PacketResource[]): boolean;
    static verifyNodataNsec3(qname: string, qtype: number, zone: string, records: PacketResource[]): boolean;
    static verifyInsecureDelegationNsec(delegationName: string, records: PacketResource[]): boolean;
    static verifyInsecureDelegationNsec3(delegationName: string, records: PacketResource[]): boolean;
    protected static _isInsecureBitmap(types: number[]): boolean;
    protected static _nsecsOnly(records: PacketResource[]): PacketResource[];
    protected static _nsec3sOnly(records: PacketResource[]): PacketResource[];
    protected static _nsec3Params(nsec3s: PacketResource[]): {
        saltHex: string;
        iterations: number;
    } | null;
    protected static _anyNsec3Matches(nsec3s: PacketResource[], target: Buffer): boolean;
    protected static _anyNsec3Covers(nsec3s: PacketResource[], target: Buffer): boolean;
    protected static _decodeNsec3NextHash(encoded: string): Buffer | null;
    protected static _extractNsec3OwnerHash(ownerName: string): Buffer | null;
    protected static _base32hexDecode(s: string): Buffer;
    protected static _stripFirstLabel(name: string): string;
    protected static _labels(name: string): string[];
    protected static _isAncestorOf(child: string, parent: string): boolean;
    protected static _nameEquals(a: string, b: string): boolean;
    protected static _normalize(name: string): string;
}
