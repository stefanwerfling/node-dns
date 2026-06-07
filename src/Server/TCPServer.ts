import {Buffer} from 'buffer';
import tcp from 'net';
import {SocketReader} from '../Lib/SocketReader.js';
import {Packet} from '../Packet/Packet.js';
import {CookieGuard, CookieRejectionReason} from './CookieGuard.js';
import {ServerOptions} from './ServerOptions.js';
import {ServerPreConnection} from './ServerPreConnection.js';
import {ServerPreRequest} from './ServerPreRequest.js';

/**
 * Reply payload accepted by the per-connection `send` callback. A single
 * Packet covers the common one-shot response case; an array is used for
 * AXFR (RFC 5936) and any other multi-message exchange — all elements are
 * written as length-prefixed frames before the connection is closed.
 *
 * A pre-encoded `Buffer` (or array of Buffers) bypasses the re-encode and
 * is the only safe way to deliver a TSIG-signed reply (RFC 8945) — the MAC
 * is bound to the exact wire bytes produced by `Tsig.sign`.
 */
export type TCPSendable = Packet | Buffer | Array<Packet | Buffer>;

/**
 * TCP Server Events.
 *
 * `request` carries the raw post-preRequest buffer as the 4th arg so handlers
 * can verify TSIG signatures against the original wire bytes (RFC 8945 — see
 * `Tsig.verify`). Re-encoding the parsed packet is not safe here because DNS
 * name compression has multiple valid representations.
 */
export type TCPServerEvents = {
    request: (
        msgRequest: Packet,
        send: (response: TCPSendable) => void,
        client: tcp.Socket,
        rawRequest: Buffer
    ) => void;
    requestError: (error: Error) => void;
    listening: () => void;
    close: () => void;
    cookieRejected: (msg: Packet, client: tcp.Socket, reason: CookieRejectionReason) => void;
};

/**
 * TCP Server
 */
export class TCPServer {

    /**
     * Internal tcp server
     * @protected
     */
    protected _tcpServer: tcp.Server;

    /**
     * Options
     * @protected
     */
    protected _options: ServerOptions|null = null;

    /**
     * pre request processor, can modify the raw buffer and override the client socket reference
     * @protected
     */
    protected _preRequest?: ServerPreRequest<tcp.Socket>;

    /**
     * pre connection processor, runs once per accepted socket (e.g. PROXY protocol)
     * @protected
     */
    protected _preConnection?: ServerPreConnection<tcp.Socket>;

    /**
     * Optional DNS Cookie validator (RFC 7873).
     * @protected
     */
    protected _cookies?: CookieGuard;

    /**
     * Constructor
     * @param {ServerOptions|null} options
     */
    public constructor(options: ServerOptions|null = null) {
        this._options = options;

        this._loadHooks();

        this._tcpServer = this._createInternalServer((socket) => {
            this._handle(socket).catch(err => {
                this._tcpServer?.emit('requestError', err instanceof Error ? err : new Error(String(err)));
            });
        });
    }

    /**
     * Read transport-specific hook options off `this._options`.
     * Overridden by subclasses (e.g. TLSServer reads from `options.tls`).
     * @protected
     */
    protected _loadHooks(): void {
        const opt = this._options?.tcp;

        if (opt && typeof opt === 'object') {
            if (opt.preRequest) {
                this._preRequest = opt.preRequest;
            }

            if (opt.preConnection) {
                this._preConnection = opt.preConnection;
            }

            if (opt.cookies) {
                this._cookies = new CookieGuard(opt.cookies);
            }
        }
    }

    /**
     * Create the underlying transport server. Overridden by subclasses
     * (e.g. TLSServer returns a `tls.Server`).
     * @param {(socket: tcp.Socket) => void} listener
     * @return {tcp.Server}
     * @protected
     */
    protected _createInternalServer(listener: (socket: tcp.Socket) => void): tcp.Server {
        return tcp.createServer(listener);
    }

    /**
     * Listen
     * @param args
     */
    public listen(...args: Parameters<tcp.Server['listen']>): this {
        this._tcpServer.listen(...args);
        return this;
    }

    /**
     * Close
     * @param callback
     */
    public close(callback?: (err?: Error) => void): void {
        this._tcpServer.close(callback);
    }

    /**
     * on
     * @param event
     * @param listener
     */
    public on<K extends keyof TCPServerEvents>(event: K, listener: TCPServerEvents[K]): this {
        this._tcpServer.on(event, listener);
        return this;
    }

    /**
     * once
     * @param event
     * @param listener
     */
    public once<K extends keyof TCPServerEvents>(event: K, listener: TCPServerEvents[K]): this {
        this._tcpServer.once(event, listener);
        return this;
    }

    /**
     * Handle client messages
     * @param {tcp.Socket} client
     * @protected
     */
    protected async _handle(client: tcp.Socket): Promise<void> {
        try {
            let emitClient = client;
            let initialBuffer: Buffer|undefined;

            if (this._preConnection) {
                const pre = await this._preConnection.process(client);

                if (pre.client) {
                    emitClient = pre.client;
                }

                initialBuffer = pre.initialBuffer;
            }

            let data = await SocketReader.readStream(client, initialBuffer);

            if (this._preRequest) {
                const result = await this._preRequest.process(data, client);
                data = result.data;

                if (result.client) {
                    emitClient = result.client;
                }
            }

            const message = Packet.parse(data);

            if (this._cookies) {
                const clientAddress = emitClient.remoteAddress ?? client.remoteAddress ?? '';
                const decision = this._cookies.evaluate(message, clientAddress);

                if (decision.action === 'badcookie') {
                    this._response(client, this._cookies.buildBadCookieResponse(
                        message,
                        decision.clientCookie,
                        decision.freshServerCookie
                    ));
                    this._tcpServer.emit('cookieRejected', message, emitClient, decision.reason);
                    return;
                }

                if (decision.action === 'refused') {
                    this._response(client, this._cookies.buildRefusedResponse(message));
                    this._tcpServer.emit('cookieRejected', message, emitClient, decision.reason);
                    return;
                }

                const send = decision.freshServerCookie !== null && decision.clientCookie !== null
                    ? this._cookieAwareSend(client, decision.clientCookie, decision.freshServerCookie)
                    : this._response.bind(this, client);

                this._tcpServer.emit('request', message, send, emitClient, data);
                return;
            }

            // Response writes go to the real socket (transport peer), while the
            // emitted client reference may be overridden by the pre-request processor.
            // The 4th arg is the raw post-preRequest buffer for TSIG verification.
            this._tcpServer.emit('request', message, this._response.bind(this, client), emitClient, data);
        } catch (e) {
            this._tcpServer.emit('requestError', e instanceof Error ? e : new Error(String(e)));
            client.destroy();
        }
    }

    /**
     * Wrap `_response` so that any Packet (or single-packet array)
     * carries the refreshed server cookie. Buffer responses (TSIG-
     * signed, pre-encoded) and multi-message arrays containing Buffers
     * pass through verbatim — re-encoding would invalidate the MAC,
     * and AXFR-style streams have their own framing concerns.
     *
     * @param {tcp.Socket} client
     * @param {Buffer} clientCookie
     * @param {Buffer} freshServerCookie
     * @return {(msg: TCPSendable) => void}
     * @protected
     */
    protected _cookieAwareSend(
        client: tcp.Socket,
        clientCookie: Buffer,
        freshServerCookie: Buffer
    ): (msg: TCPSendable) => void {
        return (msg: TCPSendable): void => {
            if (msg instanceof Packet) {
                this._cookies!.attachOrReplaceCookieOpt(msg, clientCookie, freshServerCookie);
            } else if (Array.isArray(msg) && msg.length === 1 && msg[0] instanceof Packet) {
                this._cookies!.attachOrReplaceCookieOpt(msg[0], clientCookie, freshServerCookie);
            }

            this._response(client, msg);
        };
    }

    /**
     * Handle client messages response. Accepts a single Packet (one-shot) or
     * an array (multi-message, e.g. AXFR). All packets are written as
     * length-prefixed frames; the connection is closed after the last frame.
     * @param {tcp.Socket} client
     * @param {TCPSendable} message
     * @protected
     */
    protected _response(client: tcp.Socket, message: TCPSendable): void {
        const messages = Array.isArray(message) ? message : [message];

        if (messages.length === 0) {
            client.end();
            return;
        }

        const chunks: Buffer[] = [];

        for (const m of messages) {
            const buffer = Buffer.isBuffer(m) ? m : m.toBuffer();
            const len = Buffer.alloc(2);
            len.writeUInt16BE(buffer.length);
            chunks.push(len, buffer);
        }

        client.end(Buffer.concat(chunks));
    }

    /**
     * Return the address of the server
     * @return {AddressInfo|string|null}
     */
    public address(): tcp.AddressInfo|string|null {
        return this._tcpServer.address();
    }

}