import {Buffer} from 'buffer';
import crypto from 'crypto';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {EdnsOption, EdnsOptionCode} from './EdnsECS.js';

const CLIENT_COOKIE_LEN = 8;
const SERVER_COOKIE_MIN = 8;
const SERVER_COOKIE_MAX = 32;
/**
 * Recommended server cookie length (RFC 9018 §3): SipHash-2-4 produces 64 bits;
 * we use HMAC-SHA256 truncated to 128 bits, leaving 8 bytes of metadata header
 * (version + reserved + timestamp) for a total 16 bytes.
 */
const SERVER_COOKIE_HASH_LEN = 16;
const SERVER_COOKIE_VERSION = 1;

/**
 * EDNS(0) Cookie option (RFC 7873) with RFC 9018 server-cookie construction.
 *
 * Wire format:
 *   - Client cookie: exactly 8 bytes (random per server, cached client-side)
 *   - Server cookie: 0 bytes on first query, 8..32 bytes once the server has
 *     issued one. Required on subsequent queries to bypass rate limiting.
 *
 * The server cookie helpers implement the "Hash-based" construction from
 * RFC 9018 §3, but using HMAC-SHA256 truncated to 128 bits instead of
 * SipHash-2-4 — same security goal, available in Node's `crypto` core.
 *
 * Server cookie payload layout:
 *   1 byte  version
 *   3 bytes reserved (zero)
 *   4 bytes timestamp (unix seconds, big-endian)
 *  16 bytes truncated HMAC-SHA256(secret, client_cookie || header || client_ip)
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc7873
 * @docs https://datatracker.ietf.org/doc/html/rfc9018
 */
export class EdnsCookie implements EdnsOption {

    public ednsCode: number = EdnsOptionCode.COOKIE;
    public clientCookie: Buffer;
    public serverCookie: Buffer|null;

    public constructor(clientCookie: Buffer, serverCookie: Buffer|null = null) {
        if (clientCookie.length !== CLIENT_COOKIE_LEN) {
            throw new Error(`client cookie must be ${CLIENT_COOKIE_LEN} bytes`);
        }

        if (serverCookie && (serverCookie.length < SERVER_COOKIE_MIN || serverCookie.length > SERVER_COOKIE_MAX)) {
            throw new Error(`server cookie must be ${SERVER_COOKIE_MIN}..${SERVER_COOKIE_MAX} bytes`);
        }

        this.clientCookie = clientCookie;
        this.serverCookie = serverCookie;
    }

    public static decode(reader: BufferReader, length: number): EdnsCookie {
        // Length must be 8 (client only) or 16..40 (client + 8..32 server).
        if (length !== CLIENT_COOKIE_LEN && (length < CLIENT_COOKIE_LEN + SERVER_COOKIE_MIN || length > CLIENT_COOKIE_LEN + SERVER_COOKIE_MAX)) {
            for (let i = 0; i < length; i++) {
                reader.read(8);
            }

            throw new Error(`malformed COOKIE option length ${length}`);
        }

        const clientBytes: number[] = [];

        for (let i = 0; i < CLIENT_COOKIE_LEN; i++) {
            clientBytes.push(reader.read(8));
        }

        const remaining = length - CLIENT_COOKIE_LEN;

        if (remaining === 0) {
            return new EdnsCookie(Buffer.from(clientBytes));
        }

        const serverBytes: number[] = [];

        for (let i = 0; i < remaining; i++) {
            serverBytes.push(reader.read(8));
        }

        return new EdnsCookie(Buffer.from(clientBytes), Buffer.from(serverBytes));
    }

    public encode(writer: BufferWriter): void {
        writer.writeBuffer(this.clientCookie);

        if (this.serverCookie) {
            writer.writeBuffer(this.serverCookie);
        }
    }

    /**
     * Generate a fresh 8-byte client cookie from the OS CSPRNG.
     * @return {Buffer}
     */
    public static generateClientCookie(): Buffer {
        return crypto.randomBytes(CLIENT_COOKIE_LEN);
    }

    /**
     * Compute a server cookie for the given client cookie + client IP using a
     * shared secret. Returns 24 bytes (1B version + 3B reserved + 4B timestamp
     * + 16B truncated HMAC-SHA256). The same `(clientCookie, clientIp, secret,
     * timestamp)` always yield the same cookie, which is the property
     * `verifyServerCookie` exploits.
     *
     * @param {Buffer} clientCookie 8-byte client cookie from the query
     * @param {Buffer} clientIp client IP as raw bytes (4 for IPv4, 16 for IPv6)
     * @param {Buffer} secret server secret (any length; long-lived)
     * @param {number} timestamp unix seconds, defaults to now
     * @return {Buffer}
     */
    public static computeServerCookie(
        clientCookie: Buffer,
        clientIp: Buffer,
        secret: Buffer,
        timestamp: number = Math.floor(Date.now() / 1000)
    ): Buffer {
        if (clientCookie.length !== CLIENT_COOKIE_LEN) {
            throw new Error(`client cookie must be ${CLIENT_COOKIE_LEN} bytes`);
        }

        const header = Buffer.alloc(8);
        header.writeUInt8(SERVER_COOKIE_VERSION, 0);
        // bytes 1..3 reserved, leave zero
        header.writeUInt32BE(timestamp >>> 0, 4);

        const mac = crypto.createHmac('sha256', secret)
            .update(clientCookie)
            .update(header)
            .update(clientIp)
            .digest()
            .subarray(0, SERVER_COOKIE_HASH_LEN);

        return Buffer.concat([header, mac]);
    }

    /**
     * Verify a server cookie produced by `computeServerCookie`. Recomputes
     * with the timestamp embedded in the cookie and compares the HMAC tag in
     * constant time.
     *
     * If `maxAgeSeconds` is provided, cookies older than that are rejected
     * even when the MAC matches (RFC 9018 §4.2 recommends ~1h to 1 day).
     *
     * @param {Buffer} serverCookie cookie received from the client
     * @param {Buffer} clientCookie 8-byte client cookie from the same option
     * @param {Buffer} clientIp client IP as raw bytes
     * @param {Buffer} secret server secret
     * @param {{maxAgeSeconds?: number; now?: number;}} opts
     * @return {boolean}
     */
    public static verifyServerCookie(
        serverCookie: Buffer,
        clientCookie: Buffer,
        clientIp: Buffer,
        secret: Buffer,
        opts: {maxAgeSeconds?: number; now?: number;} = {}
    ): boolean {
        if (serverCookie.length !== 8 + SERVER_COOKIE_HASH_LEN) {
            return false;
        }

        if (serverCookie.readUInt8(0) !== SERVER_COOKIE_VERSION) {
            return false;
        }

        const timestamp = serverCookie.readUInt32BE(4);

        if (opts.maxAgeSeconds !== undefined) {
            const now = opts.now ?? Math.floor(Date.now() / 1000);

            if (now - timestamp > opts.maxAgeSeconds || timestamp - now > opts.maxAgeSeconds) {
                return false;
            }
        }

        const expected = EdnsCookie.computeServerCookie(clientCookie, clientIp, secret, timestamp);

        return crypto.timingSafeEqual(serverCookie, expected);
    }

}