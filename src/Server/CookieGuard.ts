import {Buffer} from 'buffer';
import {IpBytes} from '../Lib/IpBytes.js';
import {Packet} from '../Packet/Packet.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {EDNS} from '../Packet/Types/EDNS.js';
import {EdnsCookie} from '../Packet/Types/EdnsCookie.js';
import {ServerCookieOptions} from './ServerOptions.js';

/**
 * Extended RCODE 23 (RFC 7873 §5.4) — "I see your cookie attempt but
 * cannot accept it; here is a fresh server cookie, retry". 4 bits of
 * the rcode live in the DNS header (the low nibble: 7); the upper 8
 * bits live in the OPT RR's TTL EXTENDED-RCODE byte (1).
 */
export const BADCOOKIE_RCODE: number = 23;

const REFUSED_RCODE: number = 5;

/**
 * Reason a query was rejected by the cookie validator. Emitted on
 * `'cookieRejected'` for observability — typically wired to a metric
 * counter so operators can detect spoofing pressure.
 */
export type CookieRejectionReason =
    | 'no-server-cookie'
    | 'invalid-cookie'
    | 'no-cookie-strict';

/**
 * Result of evaluating an incoming query against the cookie policy.
 * Discriminated union so TypeScript proves all three branches are
 * handled at every call site.
 */
export type CookieDecision =
    | {
        action: 'allow';
        clientCookie: Buffer | null;
        freshServerCookie: Buffer | null;
    }
    | {
        action: 'badcookie';
        reason: CookieRejectionReason;
        clientCookie: Buffer;
        freshServerCookie: Buffer;
    }
    | {
        action: 'refused';
        reason: CookieRejectionReason;
    };

/**
 * Transport-neutral DNS Cookie validator (RFC 7873 + RFC 9018).
 *
 * Owns the secret + policy and produces decisions / response packets.
 * The caller wires it into its transport: UDPServer feeds in the
 * datagram's source address; TCPServer/TLSServer pulls `socket.
 * remoteAddress`. The reject / refused responses come back as parsed
 * `Packet` objects so each transport can frame them with its native
 * `_response` path.
 *
 * Cookies on TCP/TLS aren't anti-spoofing (the handshake already
 * defeats off-path spoofing) — they provide cross-transport identity
 * (a client that fell back from UDP to TCP keeps its cookie) and
 * policy uniformity (strict mode applied consistently across both
 * legs of a hybrid deployment).
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc7873
 * @docs https://datatracker.ietf.org/doc/html/rfc9018
 */
export class CookieGuard {

    protected _config: Required<Omit<ServerCookieOptions, 'secret'>> & {secret: Buffer;};

    public constructor(options: ServerCookieOptions) {
        this._config = {
            secret: options.secret,
            mode: options.mode ?? 'lenient',
            maxAgeSeconds: options.maxAgeSeconds ?? 3600,
            udpPayloadSize: options.udpPayloadSize ?? 1232
        };
    }

    /**
     * Acceptance mode in effect — `'lenient'` lets cookieless queries
     * through, `'strict'` refuses them.
     * @return {'lenient'|'strict'}
     */
    public get mode(): 'lenient' | 'strict' {
        return this._config.mode;
    }

    /**
     * Decide what to do with an incoming query under the configured
     * cookie policy. Pure function over `(message, clientAddress)` —
     * no I/O.
     *
     * @param {Packet} message
     * @param {string} clientAddress source IP as a string (caller picks
     *   between dgram rinfo, socket.remoteAddress, or a preRequest
     *   override).
     * @return {CookieDecision}
     */
    public evaluate(message: Packet, clientAddress: string): CookieDecision {
        const incoming = CookieGuard.findCookieOption(message);

        if (incoming === null) {
            if (this._config.mode === 'strict') {
                return {action: 'refused', reason: 'no-cookie-strict'};
            }

            return {action: 'allow', clientCookie: null, freshServerCookie: null};
        }

        let clientIpBytes: Buffer;

        try {
            clientIpBytes = IpBytes.parse(clientAddress);
        } catch {
            // Malformed source address — drop the query rather than
            // baking a degenerate IP into a cookie that we can't
            // verify next time.
            return {action: 'refused', reason: 'invalid-cookie'};
        }

        const fresh = EdnsCookie.computeServerCookie(
            incoming.clientCookie,
            clientIpBytes,
            this._config.secret
        );

        if (incoming.serverCookie === null) {
            // Client has never seen us — issue a server cookie + reject
            // this query. RFC 7873 §5.2.3: the client retries with the
            // returned server cookie.
            return {
                action: 'badcookie',
                reason: 'no-server-cookie',
                clientCookie: incoming.clientCookie,
                freshServerCookie: fresh
            };
        }

        const valid = EdnsCookie.verifyServerCookie(
            incoming.serverCookie,
            incoming.clientCookie,
            clientIpBytes,
            this._config.secret,
            this._config.maxAgeSeconds > 0 ? {maxAgeSeconds: this._config.maxAgeSeconds} : {}
        );

        if (!valid) {
            return {
                action: 'badcookie',
                reason: 'invalid-cookie',
                clientCookie: incoming.clientCookie,
                freshServerCookie: fresh
            };
        }

        return {
            action: 'allow',
            clientCookie: incoming.clientCookie,
            freshServerCookie: fresh
        };
    }

    /**
     * Build an OPT pseudo-RR carrying a single COOKIE option. `extTtl`
     * lets the caller stamp an extended RCODE into the TTL (BADCOOKIE
     * = 23 → upper 8 bits = 1).
     *
     * @param {Buffer|null} clientCookie
     * @param {Buffer|null} serverCookie
     * @param {number} extTtl
     * @return {PacketResource}
     */
    public buildCookieOpt(
        clientCookie: Buffer | null,
        serverCookie: Buffer | null,
        extTtl: number
    ): PacketResource {
        const rdata = clientCookie !== null
            ? [new EdnsCookie(clientCookie, serverCookie ?? undefined)]
            : [];

        return new PacketResource(
            '',
            new EDNS(rdata),
            this._config.udpPayloadSize,
            extTtl
        );
    }

    /**
     * Mutate `response` so its OPT RR carries the given cookie option.
     * Replaces any existing cookie option to avoid drift; preserves
     * other OPT options (ECS, NSID, padding, ...) untouched.
     *
     * @param {Packet} response
     * @param {Buffer} clientCookie
     * @param {Buffer} serverCookie
     */
    public attachOrReplaceCookieOpt(
        response: Packet,
        clientCookie: Buffer,
        serverCookie: Buffer
    ): void {
        const existingIdx = response.additionals.findIndex((r) => r.packetType.type === PacketTypes.EDNS);

        if (existingIdx === -1) {
            response.additionals.push(this.buildCookieOpt(clientCookie, serverCookie, 0));
            return;
        }

        const opt = response.additionals[existingIdx].packetType as EDNS;
        const otherOptions = opt.rdata.filter((o) => !(o instanceof EdnsCookie));
        opt.rdata = [...otherOptions, new EdnsCookie(clientCookie, serverCookie)];
    }

    /**
     * Build a BADCOOKIE response packet for `request`. Header rcode
     * gets the low nibble (7) and the OPT TTL byte carries the upper
     * 8 bits (1) of extended rcode 23 (RFC 6891 §6.1.3 + RFC 7873 §5.4).
     *
     * @param {Packet} request
     * @param {Buffer} clientCookie
     * @param {Buffer} freshServerCookie
     * @return {Packet}
     */
    public buildBadCookieResponse(
        request: Packet,
        clientCookie: Buffer,
        freshServerCookie: Buffer
    ): Packet {
        const response = new Packet();
        response.header.id = request.header.id;
        response.header.qr = 1;
        response.header.opcode = request.header.opcode;
        response.header.rd = request.header.rd;
        response.header.rcode = BADCOOKIE_RCODE & 0x0F;
        response.questions = request.questions.map((q) => new PacketQuestion(q.name, q.type, q.class));
        // eslint-disable-next-line no-bitwise
        response.additionals.push(this.buildCookieOpt(clientCookie, freshServerCookie, (BADCOOKIE_RCODE >> 4) << 24));
        return response;
    }

    /**
     * Build a REFUSED response packet for `request`. No cookie option —
     * the request didn't carry a client cookie, so there's nothing to
     * bind a server cookie to.
     *
     * @param {Packet} request
     * @return {Packet}
     */
    public buildRefusedResponse(request: Packet): Packet {
        const response = new Packet();
        response.header.id = request.header.id;
        response.header.qr = 1;
        response.header.opcode = request.header.opcode;
        response.header.rd = request.header.rd;
        response.header.rcode = REFUSED_RCODE;
        response.questions = request.questions.map((q) => new PacketQuestion(q.name, q.type, q.class));
        return response;
    }

    /**
     * Scan an incoming message's additionals for an EDNS OPT RR
     * carrying a COOKIE option. Returns the cookie option or `null`.
     *
     * @param {Packet} message
     * @return {EdnsCookie|null}
     */
    public static findCookieOption(message: Packet): EdnsCookie | null {
        for (const r of message.additionals) {
            if (r.packetType.type !== PacketTypes.EDNS) {
                continue;
            }

            for (const opt of (r.packetType as EDNS).rdata) {
                if (opt instanceof EdnsCookie) {
                    return opt;
                }
            }
        }

        return null;
    }

}