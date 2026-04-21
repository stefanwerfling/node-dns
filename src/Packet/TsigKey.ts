import {Buffer} from 'buffer';

/**
 * TSIG algorithm names as they appear on the wire (canonical form, with
 * trailing dot). The `hmac-md5.sig-alg.reg.int.` string is the legacy name
 * for HMAC-MD5 (RFC 2845).
 */
export enum TsigAlgorithm {
    HMAC_MD5 = 'hmac-md5.sig-alg.reg.int.',
    HMAC_SHA1 = 'hmac-sha1.',
    HMAC_SHA224 = 'hmac-sha224.',
    HMAC_SHA256 = 'hmac-sha256.',
    HMAC_SHA384 = 'hmac-sha384.',
    HMAC_SHA512 = 'hmac-sha512.'
}

/**
 * Shared-secret key used for TSIG signing / verification.
 */
export class TsigKey {

    /**
     * Key name (e.g. "my-secondary.").
     */
    public name: string;

    /**
     * Algorithm identifier.
     */
    public algorithm: TsigAlgorithm;

    /**
     * Shared secret. Callers may pass a base64 string (typical named.conf
     * representation) or a raw Buffer.
     */
    public secret: Buffer;

    /**
     * Constructor
     * @param {string} name
     * @param {TsigAlgorithm} algorithm
     * @param {Buffer|string} secret
     */
    public constructor(name: string, algorithm: TsigAlgorithm, secret: Buffer|string) {
        this.name = name;
        this.algorithm = algorithm;
        this.secret = typeof secret === 'string' ? Buffer.from(secret, 'base64') : secret;
    }

}