import { EdnsOptionCode } from './EdnsECS.js';
export var ExtendedDnsErrorCode;
(function (ExtendedDnsErrorCode) {
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["OTHER"] = 0] = "OTHER";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["UNSUPPORTED_DNSKEY_ALGORITHM"] = 1] = "UNSUPPORTED_DNSKEY_ALGORITHM";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["UNSUPPORTED_DS_DIGEST_TYPE"] = 2] = "UNSUPPORTED_DS_DIGEST_TYPE";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["STALE_ANSWER"] = 3] = "STALE_ANSWER";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["FORGED_ANSWER"] = 4] = "FORGED_ANSWER";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["DNSSEC_INDETERMINATE"] = 5] = "DNSSEC_INDETERMINATE";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["DNSSEC_BOGUS"] = 6] = "DNSSEC_BOGUS";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["SIGNATURE_EXPIRED"] = 7] = "SIGNATURE_EXPIRED";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["SIGNATURE_NOT_YET_VALID"] = 8] = "SIGNATURE_NOT_YET_VALID";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["DNSKEY_MISSING"] = 9] = "DNSKEY_MISSING";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["RRSIGS_MISSING"] = 10] = "RRSIGS_MISSING";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["NO_ZONE_KEY_BIT_SET"] = 11] = "NO_ZONE_KEY_BIT_SET";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["NSEC_MISSING"] = 12] = "NSEC_MISSING";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["CACHED_ERROR"] = 13] = "CACHED_ERROR";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["NOT_READY"] = 14] = "NOT_READY";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["BLOCKED"] = 15] = "BLOCKED";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["CENSORED"] = 16] = "CENSORED";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["FILTERED"] = 17] = "FILTERED";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["PROHIBITED"] = 18] = "PROHIBITED";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["STALE_NXDOMAIN_ANSWER"] = 19] = "STALE_NXDOMAIN_ANSWER";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["NOT_AUTHORITATIVE"] = 20] = "NOT_AUTHORITATIVE";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["NOT_SUPPORTED"] = 21] = "NOT_SUPPORTED";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["NO_REACHABLE_AUTHORITY"] = 22] = "NO_REACHABLE_AUTHORITY";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["NETWORK_ERROR"] = 23] = "NETWORK_ERROR";
    ExtendedDnsErrorCode[ExtendedDnsErrorCode["INVALID_DATA"] = 24] = "INVALID_DATA";
})(ExtendedDnsErrorCode || (ExtendedDnsErrorCode = {}));
export class EdnsExtendedError {
    ednsCode = EdnsOptionCode.EDE;
    infoCode;
    extraText;
    constructor(infoCode = ExtendedDnsErrorCode.OTHER, extraText = '') {
        this.infoCode = infoCode;
        this.extraText = extraText;
    }
    static decode(reader, length) {
        if (length < 2) {
            for (let i = 0; i < length; i++) {
                reader.read(8);
            }
            return new EdnsExtendedError(ExtendedDnsErrorCode.OTHER, '');
        }
        const infoCode = reader.read(16);
        const textLen = length - 2;
        const bytes = [];
        for (let i = 0; i < textLen; i++) {
            bytes.push(reader.read(8));
        }
        return new EdnsExtendedError(infoCode, Buffer.from(bytes).toString('utf8'));
    }
    encode(writer) {
        writer.write(this.infoCode, 16);
        if (this.extraText.length > 0) {
            writer.writeBuffer(Buffer.from(this.extraText, 'utf8'));
        }
    }
}
//# sourceMappingURL=EdnsExtendedError.js.map