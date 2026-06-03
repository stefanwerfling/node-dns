import dgram from 'dgram';
import {Buffer} from 'buffer';
import {AddressInfo} from 'net';
import {IpBytes} from '../Lib/IpBytes.js';
import {Rrl, RrlDecision} from '../Lib/Rrl.js';
import {Packet} from '../Packet/Packet.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {EDNS} from '../Packet/Types/EDNS.js';
import {EdnsCookie} from '../Packet/Types/EdnsCookie.js';
import {ServerCookieOptions, ServerOptions} from './ServerOptions.js';
import {ServerPreRequest} from './ServerPreRequest.js';

/**
 * Extended RCODE 23 (RFC 7873 §5.4) — "I see your cookie attempt but
 * cannot accept it; here is a fresh server cookie, retry". 4 bits of
 * the rcode live in the DNS header (the low nibble: 7); the upper 8
 * bits live in the OPT RR's TTL EXTENDED-RCODE byte (1).
 */
const BADCOOKIE_RCODE: number = 23;

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
 * Reply payload accepted by the UDP `send` callback. UDP cannot stream
 * multiple datagrams as one logical reply, so when an array is passed only
 * the first element is sent and the rest are silently dropped (AXFR-style
 * multi-message responses are TCP-only by design — RFC 5936 §4.2).
 */
export type UDPSendable = Packet | Packet[] | Buffer;

/**
 * UDP Request Listener.
 *
 * `rawRequest` carries the bytes after the optional `preRequest` hook (so it
 * matches what `Packet.parse` saw). Required by RFC 8945 TSIG verification,
 * which slices the original wire bytes via `PacketResource.byteStart` rather
 * than re-encoding the parsed packet — re-encoding can produce different
 * bytes due to DNS name-compression freedom.
 */
export type UDPRequestListener = (
    msg: Packet,
    send: (msg: UDPSendable) => Promise<Buffer | void>,
    rinfo: dgram.RemoteInfo,
    rawRequest: Buffer
) => void;

/**
 * UDP Server
 */
export class UDPServer {

    /**
     * socket
     * @protected
     */
    protected _socket: dgram.Socket;

    /**
     * pre request processor, can modify the raw buffer and override the client rinfo
     * @protected
     */
    protected _preRequest?: ServerPreRequest<dgram.RemoteInfo>;

    /**
     * Optional Response Rate Limiter (RFC 5358 reflection mitigation).
     * @protected
     */
    protected _rrl?: Rrl;

    /**
     * Optional DNS Cookie validation config (RFC 7873).
     * @protected
     */
    protected _cookies?: Required<Omit<ServerCookieOptions, 'secret'>> & {secret: Buffer};

    /**
     * constructor
     * @param {ServerOptions|null} options
     */
    public constructor(options: ServerOptions|null = null) {
        let type: 'udp4' | 'udp6' = 'udp4';

        if (options && typeof options.udp === 'object') {
            if (options.udp.type) {
                type = options.udp.type;
            }

            if (options.udp.preRequest) {
                this._preRequest = options.udp.preRequest;
            }

            if (options.udp.rrl) {
                this._rrl = options.udp.rrl;
            }

            if (options.udp.cookies) {
                this._cookies = {
                    secret: options.udp.cookies.secret,
                    mode: options.udp.cookies.mode ?? 'lenient',
                    maxAgeSeconds: options.udp.cookies.maxAgeSeconds ?? 3600,
                    udpPayloadSize: options.udp.cookies.udpPayloadSize ?? 1232
                };
            }
        }

        this._socket = dgram.createSocket(type);

        this._socket.on('message', (data, rinfo) => {
            this._handle(data, rinfo).catch(e => {
                this._socket.emit('requestError', e instanceof Error ? e : new Error(String(e)));
            });
        });
    }

    /**
     * on for request
     * @param {string} event
     * @param {UDPRequestListener} listener
     * @return {UDPServer}
     */
    public on(event: 'request', listener: UDPRequestListener): this;

    /**
     * on request error
     * @param {string} event
     * @param {(err: unknown) => void} listener
     * @return {UDPServer}
     */
    public on(event: 'requestError', listener: (err: unknown) => void): this;

    /**
     * on rate-limit decision (only emitted when an `rrl` is configured and
     * fires on a non-`allow` decision). Useful for metrics and logging.
     * @param {string} event
     * @param {(msg: Packet, rinfo: dgram.RemoteInfo, decision: RrlDecision) => void} listener
     * @return {UDPServer}
     */
    public on(
        event: 'rateLimited',
        listener: (msg: Packet, rinfo: dgram.RemoteInfo, decision: Exclude<RrlDecision, 'allow'>) => void
    ): this;

    /**
     * on cookie-rejected — fires for every query that the cookie
     * validator refuses (no server cookie, invalid MAC, strict-mode
     * absent). The handler does NOT see these queries.
     * @param {string} event
     * @param {(msg: Packet, rinfo: dgram.RemoteInfo, reason: CookieRejectionReason) => void} listener
     * @return {UDPServer}
     */
    public on(
        event: 'cookieRejected',
        listener: (msg: Packet, rinfo: dgram.RemoteInfo, reason: CookieRejectionReason) => void
    ): this;

    /**
     * on
     * @param {string} event
     * @param {(...args: any[]) => void} listener
     * @return {UDPServer}
     */
    public on(event: string, listener: (...args: any[]) => void): this {
        this._socket.on(event, listener);
        return this;
    }

    /**
     * once
     * @param {string} event
     * @param {(...args: any[]) => void} listener
     * @return {UDPServer}
     */
    public once(event: string, listener: (...args: any[]) => void): this {
        this._socket.once(event, listener);
        return this;
    }

    /**
     * handle
     * @param {Buffer} data
     * @param {dgram.RemoteInfo} rinfo
     * @protected
     */
    protected async _handle(data: Buffer, rinfo: dgram.RemoteInfo): Promise<void> {
        try {
            let tdata = data;
            let emitRinfo = rinfo;

            if (this._preRequest) {
                const result = await this._preRequest.process(tdata, rinfo);
                tdata = result.data;

                if (result.client) {
                    emitRinfo = result.client;
                }
            }

            const message = Packet.parse(tdata);

            if (this._rrl) {
                const qtype = message.questions[0]?.type ?? 0;
                const decision = this._rrl.check(emitRinfo.address, qtype);

                if (decision === 'drop') {
                    this._socket.emit('rateLimited', message, emitRinfo, decision);
                    return;
                }

                if (decision === 'truncate') {
                    await this._sendTruncated(rinfo, message);
                    this._socket.emit('rateLimited', message, emitRinfo, decision);
                    return;
                }
            }

            if (this._cookies) {
                const decision = this._evaluateCookie(message, emitRinfo.address);

                if (decision.action === 'badcookie') {
                    await this._sendCookieReject(rinfo, message, BADCOOKIE_RCODE, decision.clientCookie, decision.freshServerCookie);
                    this._socket.emit('cookieRejected', message, emitRinfo, decision.reason);
                    return;
                }

                if (decision.action === 'refused') {
                    await this._sendCookieReject(rinfo, message, 5 /* REFUSED */, null, null);
                    this._socket.emit('cookieRejected', message, emitRinfo, decision.reason);
                    return;
                }

                // decision.action === 'allow' — wrap send so the response
                // carries the refreshed server cookie when the request
                // did, and pass through.
                const send = decision.freshServerCookie !== null && decision.clientCookie !== null
                    ? this._cookieAwareSend(rinfo, decision.clientCookie, decision.freshServerCookie)
                    : this._response.bind(this, rinfo);

                this._socket.emit('request', message, send, emitRinfo, tdata);
                return;
            }

            // Response always goes back to the transport peer (e.g. the proxy),
            // while the emitted rinfo reflects the (optionally overridden) client.
            // The 4th arg is the raw post-preRequest buffer for TSIG verification.
            this._socket.emit('request', message, this._response.bind(this, rinfo), emitRinfo, tdata);
        } catch (e) {
            this._socket.emit('requestError', e instanceof Error ? e : new Error(String(e)));
        }
    }

    /**
     * Decide what to do with an incoming query under the configured
     * cookie policy. Returns an action discriminator + the cookie
     * material the calling code needs to act on it.
     *
     * @param {Packet} message
     * @param {string} clientAddress
     * @return {{action: 'allow'|'badcookie'|'refused'; reason?: CookieRejectionReason; clientCookie: Buffer | null; freshServerCookie: Buffer | null;}}
     * @protected
     */
    protected _evaluateCookie(
        message: Packet,
        clientAddress: string
    ): {
        action: 'allow' | 'badcookie' | 'refused';
        reason?: CookieRejectionReason;
        clientCookie: Buffer | null;
        freshServerCookie: Buffer | null;
    } {
        const incoming = UDPServer._findCookieOption(message);

        if (incoming === null) {
            if (this._cookies!.mode === 'strict') {
                return {action: 'refused', reason: 'no-cookie-strict', clientCookie: null, freshServerCookie: null};
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
            return {action: 'refused', reason: 'invalid-cookie', clientCookie: null, freshServerCookie: null};
        }

        const fresh = EdnsCookie.computeServerCookie(
            incoming.clientCookie,
            clientIpBytes,
            this._cookies!.secret
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
            this._cookies!.secret,
            this._cookies!.maxAgeSeconds > 0 ? {maxAgeSeconds: this._cookies!.maxAgeSeconds} : {}
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
     * Build + send a short DNS response that carries an EDNS cookie
     * for the client. Used for both BADCOOKIE (RFC 7873) and
     * strict-mode REFUSED.
     *
     * @param {dgram.RemoteInfo} rinfo
     * @param {Packet} request
     * @param {number} rcode 5 (REFUSED) or 23 (BADCOOKIE)
     * @param {Buffer|null} clientCookie
     * @param {Buffer|null} freshServerCookie
     * @return {Promise<Buffer|void>}
     * @protected
     */
    protected _sendCookieReject(
        rinfo: dgram.RemoteInfo,
        request: Packet,
        rcode: number,
        clientCookie: Buffer | null,
        freshServerCookie: Buffer | null
    ): Promise<Buffer|void> {
        const response = new Packet();
        response.header.id = request.header.id;
        response.header.qr = 1;
        response.header.opcode = request.header.opcode;
        response.header.rd = request.header.rd;
        response.questions = request.questions.map((q) => new PacketQuestion(q.name, q.type, q.class));

        if (rcode === BADCOOKIE_RCODE) {
            // Low 4 bits → header.rcode; upper 8 bits → OPT TTL.
            response.header.rcode = rcode & 0x0F;
            response.additionals.push(this._buildCookieOpt(
                clientCookie,
                freshServerCookie,
                (rcode >> 4) << 24
            ));
        } else {
            response.header.rcode = rcode;

            if (clientCookie !== null && freshServerCookie !== null) {
                response.additionals.push(this._buildCookieOpt(clientCookie, freshServerCookie, 0));
            }
        }

        return this._response(rinfo, response);
    }

    /**
     * Wrap the standard `_response` so that any Packet response
     * automatically carries the refreshed server cookie. Buffer
     * responses (TSIG-signed, pre-encoded) are passed through
     * verbatim — re-encoding would invalidate the MAC.
     *
     * @param {dgram.RemoteInfo} rinfo
     * @param {Buffer} clientCookie
     * @param {Buffer} freshServerCookie
     * @return {(msg: UDPSendable) => Promise<Buffer|void>}
     * @protected
     */
    protected _cookieAwareSend(
        rinfo: dgram.RemoteInfo,
        clientCookie: Buffer,
        freshServerCookie: Buffer
    ): (msg: UDPSendable) => Promise<Buffer|void> {
        return (msg: UDPSendable): Promise<Buffer|void> => {
            let payload: Packet|Buffer;

            if (Array.isArray(msg)) {
                payload = msg[0];
            } else {
                payload = msg;
            }

            if (payload instanceof Packet) {
                this._attachOrReplaceCookieOpt(payload, clientCookie, freshServerCookie);
            }

            return this._response(rinfo, payload);
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
     * @protected
     */
    protected _buildCookieOpt(
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
            this._cookies!.udpPayloadSize,
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
     * @protected
     */
    protected _attachOrReplaceCookieOpt(
        response: Packet,
        clientCookie: Buffer,
        serverCookie: Buffer
    ): void {
        const existingIdx = response.additionals.findIndex((r) => r.packetType.type === PacketTypes.EDNS);

        if (existingIdx === -1) {
            response.additionals.push(this._buildCookieOpt(clientCookie, serverCookie, 0));
            return;
        }

        const opt = response.additionals[existingIdx].packetType as EDNS;
        const otherOptions = opt.rdata.filter((o) => !(o instanceof EdnsCookie));
        opt.rdata = [...otherOptions, new EdnsCookie(clientCookie, serverCookie)];
    }

    /**
     * Scan an incoming message's additionals for an EDNS OPT RR
     * carrying a COOKIE option. Returns the cookie option or `null`.
     *
     * @param {Packet} message
     * @return {EdnsCookie|null}
     * @protected
     */
    protected static _findCookieOption(message: Packet): EdnsCookie | null {
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

    /**
     * Build and send a TC=1 (truncated) response for the given query. Used
     * by the RRL slip path: the client retries the same query over TCP,
     * which is much harder to spoof and so cannot be amplified.
     * @param {dgram.RemoteInfo} rinfo transport peer the datagram is sent to
     * @param {Packet} request the parsed query
     * @return {Promise<Buffer|void>}
     * @protected
     */
    protected _sendTruncated(rinfo: dgram.RemoteInfo, request: Packet): Promise<Buffer|void> {
        const trunc = new Packet();
        trunc.header.id = request.header.id;
        trunc.header.qr = 1;
        trunc.header.opcode = request.header.opcode;
        trunc.header.tc = 1;
        trunc.header.rd = request.header.rd;
        trunc.questions = request.questions.slice();
        return this._response(rinfo, trunc);
    }

    /**
     * response
     * @param {dgram.RemoteInfo} rinfo
     * @param {UDPSendable} message single packet, packet array (only first
     *        used) or pre-encoded buffer
     * @return {Buffer}
     * @protected
     */
    protected _response(rinfo: dgram.RemoteInfo, message: UDPSendable): Promise<Buffer|void> {
        let payload: Packet|Buffer;

        if (Array.isArray(message)) {
            // AXFR-style multi-message responses don't fit into a UDP datagram;
            // honour the first packet and drop the rest.
            payload = message[0];
        } else {
            payload = message;
        }

        const tmessage = payload instanceof Packet ? payload.toBuffer() : payload;

        return new Promise((resolve, reject) => {
            this._socket.send(tmessage, rinfo.port, rinfo.address, (err): void => {
                if (err) {
                    return reject(err);
                }

                return resolve(tmessage);
            });
        });
    }

    /**
     * listen
     * @param {number} port
     * @param {[string]} address
     */
    public listen(port: number, address?: string): Promise<void> {
        return new Promise(resolve => {
            this._socket.bind(port, address, resolve);
        });
    }

    /**
     * close
     * @param {[() => void]} callback
     */
    public close(callback?: () => void): void {
        this._socket.close(callback);
    }

    /**
     * Return the address of the server
     * @return {AddressInfo}
     */
    public address(): AddressInfo {
        return this._socket.address() as AddressInfo;
    }

}