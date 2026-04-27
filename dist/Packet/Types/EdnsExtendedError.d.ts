import { BufferReader } from '../../Lib/BufferReader.js';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { EdnsOption } from './EdnsECS.js';
export declare enum ExtendedDnsErrorCode {
    OTHER = 0,
    UNSUPPORTED_DNSKEY_ALGORITHM = 1,
    UNSUPPORTED_DS_DIGEST_TYPE = 2,
    STALE_ANSWER = 3,
    FORGED_ANSWER = 4,
    DNSSEC_INDETERMINATE = 5,
    DNSSEC_BOGUS = 6,
    SIGNATURE_EXPIRED = 7,
    SIGNATURE_NOT_YET_VALID = 8,
    DNSKEY_MISSING = 9,
    RRSIGS_MISSING = 10,
    NO_ZONE_KEY_BIT_SET = 11,
    NSEC_MISSING = 12,
    CACHED_ERROR = 13,
    NOT_READY = 14,
    BLOCKED = 15,
    CENSORED = 16,
    FILTERED = 17,
    PROHIBITED = 18,
    STALE_NXDOMAIN_ANSWER = 19,
    NOT_AUTHORITATIVE = 20,
    NOT_SUPPORTED = 21,
    NO_REACHABLE_AUTHORITY = 22,
    NETWORK_ERROR = 23,
    INVALID_DATA = 24
}
export declare class EdnsExtendedError implements EdnsOption {
    ednsCode: number;
    infoCode: number;
    extraText: string;
    constructor(infoCode?: number, extraText?: string);
    static decode(reader: BufferReader, length: number): EdnsExtendedError;
    encode(writer: BufferWriter): void;
}
