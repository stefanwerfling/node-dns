import { Buffer } from 'buffer';
export declare enum TsigAlgorithm {
    HMAC_MD5 = "hmac-md5.sig-alg.reg.int.",
    HMAC_SHA1 = "hmac-sha1.",
    HMAC_SHA224 = "hmac-sha224.",
    HMAC_SHA256 = "hmac-sha256.",
    HMAC_SHA384 = "hmac-sha384.",
    HMAC_SHA512 = "hmac-sha512."
}
export declare class TsigKey {
    name: string;
    algorithm: TsigAlgorithm;
    secret: Buffer;
    constructor(name: string, algorithm: TsigAlgorithm, secret: Buffer | string);
}
