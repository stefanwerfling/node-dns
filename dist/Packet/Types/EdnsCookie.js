import { Buffer } from 'buffer';
import crypto from 'crypto';
import { EdnsOptionCode } from './EdnsECS.js';
const CLIENT_COOKIE_LEN = 8;
const SERVER_COOKIE_MIN = 8;
const SERVER_COOKIE_MAX = 32;
const SERVER_COOKIE_HASH_LEN = 16;
const SERVER_COOKIE_VERSION = 1;
export class EdnsCookie {
    ednsCode = EdnsOptionCode.COOKIE;
    clientCookie;
    serverCookie;
    constructor(clientCookie, serverCookie = null) {
        if (clientCookie.length !== CLIENT_COOKIE_LEN) {
            throw new Error(`client cookie must be ${CLIENT_COOKIE_LEN} bytes`);
        }
        if (serverCookie && (serverCookie.length < SERVER_COOKIE_MIN || serverCookie.length > SERVER_COOKIE_MAX)) {
            throw new Error(`server cookie must be ${SERVER_COOKIE_MIN}..${SERVER_COOKIE_MAX} bytes`);
        }
        this.clientCookie = clientCookie;
        this.serverCookie = serverCookie;
    }
    static decode(reader, length) {
        if (length !== CLIENT_COOKIE_LEN && (length < CLIENT_COOKIE_LEN + SERVER_COOKIE_MIN || length > CLIENT_COOKIE_LEN + SERVER_COOKIE_MAX)) {
            for (let i = 0; i < length; i++) {
                reader.read(8);
            }
            throw new Error(`malformed COOKIE option length ${length}`);
        }
        const clientBytes = [];
        for (let i = 0; i < CLIENT_COOKIE_LEN; i++) {
            clientBytes.push(reader.read(8));
        }
        const remaining = length - CLIENT_COOKIE_LEN;
        if (remaining === 0) {
            return new EdnsCookie(Buffer.from(clientBytes));
        }
        const serverBytes = [];
        for (let i = 0; i < remaining; i++) {
            serverBytes.push(reader.read(8));
        }
        return new EdnsCookie(Buffer.from(clientBytes), Buffer.from(serverBytes));
    }
    encode(writer) {
        writer.writeBuffer(this.clientCookie);
        if (this.serverCookie) {
            writer.writeBuffer(this.serverCookie);
        }
    }
    static generateClientCookie() {
        return crypto.randomBytes(CLIENT_COOKIE_LEN);
    }
    static computeServerCookie(clientCookie, clientIp, secret, timestamp = Math.floor(Date.now() / 1000)) {
        if (clientCookie.length !== CLIENT_COOKIE_LEN) {
            throw new Error(`client cookie must be ${CLIENT_COOKIE_LEN} bytes`);
        }
        const header = Buffer.alloc(8);
        header.writeUInt8(SERVER_COOKIE_VERSION, 0);
        header.writeUInt32BE(timestamp >>> 0, 4);
        const mac = crypto.createHmac('sha256', secret)
            .update(clientCookie)
            .update(header)
            .update(clientIp)
            .digest()
            .subarray(0, SERVER_COOKIE_HASH_LEN);
        return Buffer.concat([header, mac]);
    }
    static verifyServerCookie(serverCookie, clientCookie, clientIp, secret, opts = {}) {
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
//# sourceMappingURL=EdnsCookie.js.map