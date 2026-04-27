import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {EdnsOption, EdnsOptionCode} from './EdnsECS.js';

/**
 * EDNS(0) Extended DNS Error (EDE) info codes (RFC 8914).
 * @docs https://datatracker.ietf.org/doc/html/rfc8914
 */
export enum ExtendedDnsErrorCode {
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

/**
 * EDNS(0) Extended DNS Error option (RFC 8914).
 *
 * Carries a 16-bit info code and optional UTF-8 extra text. Servers attach it
 * to a response (typically with SERVFAIL) to explain *why* a query failed —
 * useful for DNSSEC validation diagnostics, RPZ blocks, etc.
 */
export class EdnsExtendedError implements EdnsOption {

    public ednsCode: number = EdnsOptionCode.EDE;
    public infoCode: number;
    public extraText: string;

    public constructor(infoCode: number = ExtendedDnsErrorCode.OTHER, extraText: string = '') {
        this.infoCode = infoCode;
        this.extraText = extraText;
    }

    public static decode(reader: BufferReader, length: number): EdnsExtendedError {
        if (length < 2) {
            // Malformed; consume what's there and return a placeholder so the
            // outer EDNS decode loop stays aligned.
            for (let i = 0; i < length; i++) {
                reader.read(8);
            }

            return new EdnsExtendedError(ExtendedDnsErrorCode.OTHER, '');
        }

        const infoCode = reader.read(16);
        const textLen = length - 2;
        const bytes: number[] = [];

        for (let i = 0; i < textLen; i++) {
            bytes.push(reader.read(8));
        }

        return new EdnsExtendedError(infoCode, Buffer.from(bytes).toString('utf8'));
    }

    public encode(writer: BufferWriter): void {
        writer.write(this.infoCode, 16);

        if (this.extraText.length > 0) {
            writer.writeBuffer(Buffer.from(this.extraText, 'utf8'));
        }
    }

}