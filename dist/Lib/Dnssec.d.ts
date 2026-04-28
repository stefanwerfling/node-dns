import { Buffer } from 'buffer';
import * as crypto from 'crypto';
import { PacketResource } from '../Packet/PacketResource.js';
import { DNSKEY } from '../Packet/Types/DNSKEY.js';
import { DS } from '../Packet/Types/DS.js';
import { RRSIG } from '../Packet/Types/RRSIG.js';
export declare enum DnssecAlgorithm {
    RSASHA256 = 8,
    RSASHA512 = 10,
    ECDSAP256SHA256 = 13,
    ECDSAP384SHA384 = 14,
    ED25519 = 15
}
export declare enum DnssecDigest {
    SHA1 = 1,
    SHA256 = 2,
    SHA384 = 4
}
export type DnssecVerifyOptions = {
    now?: number;
    skipValidityWindow?: boolean;
};
export declare class Dnssec {
    protected static readonly _RAW_CANONICAL_TYPES: ReadonlySet<number>;
    static computeKeyTag(dnskey: DNSKEY): number;
    static computeDsDigest(owner: string, dnskey: DNSKEY, digestType: number): string;
    static verifyDs(owner: string, dnskey: DNSKEY, ds: DS): boolean;
    static verifyRrsig(owner: string, rrset: PacketResource[], rrsig: RRSIG, dnskey: DNSKEY, options?: DnssecVerifyOptions): boolean;
    static buildSigningInput(owner: string, rrset: PacketResource[], rrsig: RRSIG): Buffer;
    static canonicalNameCompare(a: string, b: string): number;
    static nsecCovers(ownerName: string, nextDomain: string, queryName: string): boolean;
    static nsec3Hash(name: string, saltHex: string, iterations: number, algorithm?: number): Buffer;
    static nsec3CoversHash(ownerHash: Buffer, nextHash: Buffer, queryHash: Buffer): boolean;
    static base32hexEncode(buf: Buffer): string;
    protected static _reconstructSignedOwner(owner: string, signerLabels: number): string;
    protected static _rrsigSignedHeader(rrsig: RRSIG): Buffer;
    protected static _canonicalNameBytes(name: string): Buffer;
    protected static _canonicalRdataBytes(resource: PacketResource): Buffer;
    protected static _dnskeyRdataBytes(dnskey: DNSKEY): Buffer;
    protected static _hashNameForDigest(digestType: number): string;
    protected static _parseSigDate(value: string): number;
    protected static _verifyAlgorithm(algorithm: number, input: Buffer, signature: Buffer, dnskey: DNSKEY): boolean;
    protected static _rsaPublicKey(dnskey: DNSKEY): crypto.KeyObject;
    protected static _ecdsaPublicKey(dnskey: DNSKEY, curveBytes: number, jwkCurve: 'P-256' | 'P-384'): crypto.KeyObject;
    protected static _ed25519PublicKey(dnskey: DNSKEY): crypto.KeyObject;
}
