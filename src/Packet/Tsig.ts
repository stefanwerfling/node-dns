import {Buffer} from 'buffer';
import {createHmac, timingSafeEqual} from 'crypto';
import {BufferWriter} from '../Lib/BufferWriter.js';
import {Packet} from './Packet.js';
import {PacketClass} from './PacketClass.js';
import {PacketName} from './PacketName.js';
import {PacketResource} from './PacketResource.js';
import {TsigAlgorithm, TsigKey} from './TsigKey.js';
import {TSIG, TsigError} from './Types/TSIG.js';

/**
 * Sign options.
 */
export type TsigSignOptions = {
    /**
     * Unix time used as TimeSigned. Defaults to current wall-clock time.
     */
    timeSigned?: number;

    /**
     * Allowed clock skew (seconds) advertised in the TSIG record.
     */
    fudge?: number;

    /**
     * When signing a response, pass the MAC of the request being responded
     * to. It is prepended to the HMAC input (RFC 8945 §5.3.2.3).
     */
    requestMac?: Buffer;

    /**
     * Override the TSIG error code. Typically 0 (NOERROR); set to BADTIME
     * or BADKEY when building an error response.
     */
    error?: number;

    /**
     * Opaque otherData field (used with BADTIME to carry the server time).
     */
    otherData?: Buffer;
};

/**
 * Sign result.
 */
export type TsigSignResult = {
    /**
     * Full wire-format message with the TSIG RR appended.
     */
    buffer: Buffer;

    /**
     * The MAC computed for this message. Store it when sending a request
     * so you can pass it back to `verify(..., {requestMac})` on the
     * response.
     */
    mac: Buffer;

    /**
     * The TSIG record that was appended (also pushed onto
     * `packet.additionals`).
     */
    tsig: TSIG;
};

/**
 * Verify options.
 */
export type TsigVerifyOptions = {
    /**
     * If verifying a response, the MAC of the request being responded to.
     */
    requestMac?: Buffer;

    /**
     * Current Unix time for the fudge-window check. Defaults to wall-clock.
     */
    now?: number;

    /**
     * Disable the clock-skew check entirely (useful for replaying recorded
     * traffic during tests).
     */
    skipTimeCheck?: boolean;
};

/**
 * Verify result.
 */
export type TsigVerifyResult = {
    valid: boolean;

    /**
     * Failure reason when `valid` is false.
     */
    reason?: string;

    /**
     * Parsed TSIG record (present whenever one was found, regardless of
     * the signature outcome).
     */
    tsig?: TSIG;
};

/**
 * TSIG signing / verification (RFC 8945).
 */
export class Tsig {

    /**
     * Byte offset of ARCOUNT inside the DNS header.
     */
    protected static readonly ARCOUNT_OFFSET: number = 10;

    /**
     * Canonicalise a domain-name string for comparison — lowercase, without
     * the trailing root-label dot (which `PacketName.decode` omits).
     * @param {string} name
     * @return {string}
     */
    protected static canonicalName(name: string): string {
        const lower = name.toLowerCase();
        return lower.endsWith('.') ? lower.slice(0, -1) : lower;
    }

    /**
     * Map TSIG algorithm names to Node's crypto HMAC hash identifiers.
     * @param {string} algorithm
     * @return {string}
     */
    public static hashName(algorithm: string): string {
        const lowered = Tsig.canonicalName(algorithm);

        switch (lowered) {
            case Tsig.canonicalName(TsigAlgorithm.HMAC_MD5):
                return 'md5';
            case Tsig.canonicalName(TsigAlgorithm.HMAC_SHA1):
                return 'sha1';
            case Tsig.canonicalName(TsigAlgorithm.HMAC_SHA224):
                return 'sha224';
            case Tsig.canonicalName(TsigAlgorithm.HMAC_SHA256):
                return 'sha256';
            case Tsig.canonicalName(TsigAlgorithm.HMAC_SHA384):
                return 'sha384';
            case Tsig.canonicalName(TsigAlgorithm.HMAC_SHA512):
                return 'sha512';
            default:
                throw new Error(`TSIG: unsupported algorithm "${algorithm}"`);
        }
    }

    /**
     * Encode the TSIG variables used as HMAC input (RFC 8945 §5.3.2.2).
     * @param {string} keyName
     * @param {string} algorithm
     * @param {number} timeSigned
     * @param {number} fudge
     * @param {number} error
     * @param {Buffer} otherData
     * @return {Buffer}
     */
    protected static encodeTsigVariables(
        keyName: string,
        algorithm: string,
        timeSigned: number,
        fudge: number,
        error: number,
        otherData: Buffer
    ): Buffer {
        const writer = new BufferWriter();

        // Key name, canonical form (lowercase, uncompressed).
        PacketName.encode(keyName.toLowerCase(), writer);

        // Class and TTL, constants for TSIG.
        writer.write(PacketClass.ANY, 16);
        writer.write(0, 32);

        // Algorithm name, canonical form.
        PacketName.encode(algorithm.toLowerCase(), writer);

        // TimeSigned (uint48) as (hi uint16, lo uint32).
        const divisor = 0x100000000;
        writer.write(Math.floor(timeSigned / divisor), 16);
        writer.write(timeSigned % divisor, 32);

        writer.write(fudge, 16);
        writer.write(error, 16);
        writer.write(otherData.length, 16);

        if (otherData.length > 0) {
            writer.writeBuffer(otherData);
        }

        return writer.toBuffer();
    }

    /**
     * Append 2-byte size + `mac` bytes to the given writer input (prefix
     * used when signing / verifying responses).
     * @param {Buffer} mac
     * @return {Buffer}
     */
    protected static encodeRequestMacPrefix(mac: Buffer): Buffer {
        const prefix = Buffer.alloc(2 + mac.length);
        prefix.writeUInt16BE(mac.length, 0);
        mac.copy(prefix, 2);
        return prefix;
    }

    /**
     * Sign a DNS message, appending a TSIG RR. On success the `Packet`
     * instance gets the TSIG RR pushed onto its `additionals` array so that
     * the caller's view matches the wire bytes returned.
     * @param {Packet} packet
     * @param {TsigKey} key
     * @param {TsigSignOptions} options
     * @return {TsigSignResult}
     */
    public static sign(packet: Packet, key: TsigKey, options: TsigSignOptions = {}): TsigSignResult {
        const timeSigned = options.timeSigned === undefined ? Math.floor(Date.now() / 1000) : options.timeSigned;
        const fudge = options.fudge === undefined ? 300 : options.fudge;
        const error = options.error === undefined ? TsigError.NOERROR : options.error;
        const otherData = options.otherData === undefined ? Buffer.alloc(0) : options.otherData;

        // Build wire bytes without TSIG. ARCOUNT reflects non-TSIG additionals.
        const preBytes = packet.toBuffer();

        // Patch ARCOUNT to reflect the TSIG that will follow (RFC 8945 §5.3.2).
        const macInputMsg = Buffer.from(preBytes);
        macInputMsg.writeUInt16BE(packet.header.arcount + 1, Tsig.ARCOUNT_OFFSET);

        const tsigVars = Tsig.encodeTsigVariables(
            key.name, key.algorithm, timeSigned, fudge, error, otherData
        );

        const hmac = createHmac(Tsig.hashName(key.algorithm), key.secret);

        if (options.requestMac) {
            hmac.update(Tsig.encodeRequestMacPrefix(options.requestMac));
        }

        hmac.update(macInputMsg);
        hmac.update(tsigVars);

        const mac = hmac.digest();

        const tsigRecord = new TSIG(
            key.algorithm, timeSigned, fudge, mac,
            packet.header.id, error, otherData
        );
        const tsigResource = new PacketResource(key.name, tsigRecord, PacketClass.ANY, 0);

        // Encode the TSIG RR with a fresh writer — uncompressed, independent
        // of the main packet's writer state.
        const tsigRRBytes = PacketResource.encode(tsigResource);

        // Final buffer = original preBytes (with ARCOUNT+1) + TSIG RR.
        const final = Buffer.concat([macInputMsg, tsigRRBytes]);

        // Keep the Packet instance in sync with the wire output.
        packet.additionals.push(tsigResource);
        packet.header.arcount = packet.additionals.length;

        return {
            buffer: final,
            mac: mac,
            tsig: tsigRecord
        };
    }

    /**
     * Verify a received DNS message that carries a TSIG RR.
     *
     * Returns `valid: false` with a reason string for any failure
     * (missing TSIG, unknown algorithm, key mismatch, bad MAC, bad time).
     *
     * @param {Packet} packet parsed packet (via Packet.parse on receivedBytes)
     * @param {Buffer} receivedBytes original wire-format bytes
     * @param {TsigKey} key expected shared-secret key
     * @param {TsigVerifyOptions} options
     * @return {TsigVerifyResult}
     */
    public static verify(
        packet: Packet,
        receivedBytes: Buffer,
        key: TsigKey,
        options: TsigVerifyOptions = {}
    ): TsigVerifyResult {
        const lastAdd = packet.additionals[packet.additionals.length - 1];

        if (!lastAdd || !(lastAdd.packetType instanceof TSIG)) {
            return {
                valid: false,
                reason: 'no TSIG record at the end of the Additional section'
            };
        }

        const tsig = lastAdd.packetType;

        if (lastAdd.byteStart === undefined) {
            return {
                valid: false,
                reason: 'TSIG resource has no byteStart offset (parse via Packet.parse)',
                tsig: tsig
            };
        }

        if (Tsig.canonicalName(lastAdd.name) !== Tsig.canonicalName(key.name)) {
            return {
                valid: false,
                reason: `TSIG key name mismatch: expected ${key.name}, got ${lastAdd.name}`,
                tsig: tsig
            };
        }

        if (Tsig.canonicalName(tsig.algorithm) !== Tsig.canonicalName(key.algorithm)) {
            return {
                valid: false,
                reason: `TSIG algorithm mismatch: expected ${key.algorithm}, got ${tsig.algorithm}`,
                tsig: tsig
            };
        }

        if (!options.skipTimeCheck) {
            const now = options.now === undefined ? Math.floor(Date.now() / 1000) : options.now;
            const delta = Math.abs(now - tsig.timeSigned);

            if (delta > tsig.fudge) {
                return {
                    valid: false,
                    reason: `TSIG timestamp outside fudge window (delta=${delta}s, fudge=${tsig.fudge}s)`,
                    tsig: tsig
                };
            }
        }

        const sliceEnd = lastAdd.byteStart;

        if (sliceEnd > receivedBytes.length) {
            return {
                valid: false,
                reason: 'TSIG offset beyond buffer',
                tsig: tsig
            };
        }

        const macInput = receivedBytes.subarray(0, sliceEnd);

        const tsigVars = Tsig.encodeTsigVariables(
            lastAdd.name, tsig.algorithm,
            tsig.timeSigned, tsig.fudge, tsig.error, tsig.otherData
        );

        let hashName: string;

        try {
            hashName = Tsig.hashName(tsig.algorithm);
        } catch (e) {
            return {
                valid: false,
                reason: e instanceof Error ? e.message : String(e),
                tsig: tsig
            };
        }

        const hmac = createHmac(hashName, key.secret);

        if (options.requestMac) {
            hmac.update(Tsig.encodeRequestMacPrefix(options.requestMac));
        }

        hmac.update(macInput);
        hmac.update(tsigVars);

        const expected = hmac.digest();

        if (expected.length !== tsig.mac.length || !timingSafeEqual(expected, tsig.mac)) {
            return {
                valid: false,
                reason: 'TSIG MAC verification failed',
                tsig: tsig
            };
        }

        return {
            valid: true,
            tsig: tsig
        };
    }

}