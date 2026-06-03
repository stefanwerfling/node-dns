import {Buffer} from 'buffer';
import {EventEmitter} from 'events';
import net from 'net';
import tls from 'tls';
import {DsoMessage, KeepaliveTlv, PushTlv, ReconfirmTlv, RetryDelayTlv, SubscribeTlv, UnsubscribeTlv} from '../Lib/Dso.js';
import {PacketResource} from '../Packet/PacketResource.js';

export type PushServerOptions = {

    /**
     * TLS context — at minimum `{cert, key}`. RFC 8765 mandates TLS.
     */
    tls: tls.TlsOptions;

    /**
     * Inactivity timeout (ms) sent back to the client in the
     * KEEPALIVE TLV response when the client advertises one. Default:
     * 30 minutes. RFC 8490 §7.1.1: the server's value wins when it's
     * smaller than the client's request.
     */
    inactivityMs?: number;

    /**
     * Keepalive interval (ms) sent back to the client. Default: 15
     * seconds.
     */
    keepaliveMs?: number;
};

/**
 * One server-side subscription. Reflects what the client asked for —
 * the server maintains a set of these per connection so a `notify()`
 * call can fan out to every connection with a matching subscription.
 */
type ServerSubscription = {
    name: string;
    qtype: number;
    qclass: number;
    messageId: number;
};

/**
 * Per-connection state. Owns the framing buffer + subscription set
 * for one DSO session.
 */
class PushSession extends EventEmitter {

    public readonly socket: tls.TLSSocket;
    public readonly subscriptions: Map<number, ServerSubscription>;
    protected _readBuffer: Buffer;
    protected _expected: number | null;
    protected _server: PushServer;
    protected _closed: boolean;

    public constructor(server: PushServer, socket: tls.TLSSocket) {
        super();
        this._server = server;
        this.socket = socket;
        this.subscriptions = new Map();
        this._readBuffer = Buffer.alloc(0);
        this._expected = null;
        this._closed = false;

        socket.on('data', (chunk: Buffer): void => {
            this._readBuffer = this._readBuffer.length === 0 ? chunk : Buffer.concat([this._readBuffer, chunk]);
            this._drainFrames();
        });

        socket.once('error', (err): void => {
            this._teardown(err);
        });

        socket.once('close', (): void => {
            this._teardown();
        });
    }

    public sendMessage(message: DsoMessage): void {
        if (this._closed || this.socket.destroyed) {
            return;
        }

        const body = message.toBuffer();
        const frame = Buffer.alloc(2 + body.length);
        frame.writeUInt16BE(body.length, 0);
        body.copy(frame, 2);
        this.socket.write(frame);
    }

    /**
     * Send a unilateral RETRY_DELAY TLV (RFC 8490 §7.2) telling this
     * client to back off for `retryDelayMs` before reconnecting. The
     * server typically follows this with a session close — pass
     * `closeAfter: true` to chain the close after the bytes flush.
     */
    public sendRetryDelay(retryDelayMs: number, closeAfter: boolean = false): void {
        const message = DsoMessage.unilateral(new RetryDelayTlv(retryDelayMs));
        this.sendMessage(message);

        if (closeAfter) {
            // Let the kernel flush the frame before tearing down so
            // the RETRY_DELAY actually reaches the client.
            setImmediate((): void => this._teardown());
        }
    }

    public close(): void {
        this._teardown();
    }

    public get closed(): boolean {
        return this._closed;
    }

    protected _drainFrames(): void {
        while (true) {
            if (this._expected === null) {
                if (this._readBuffer.length < 2) {
                    return;
                }

                this._expected = this._readBuffer.readUInt16BE(0);
                this._readBuffer = this._readBuffer.subarray(2);
            }

            if (this._readBuffer.length < this._expected) {
                return;
            }

            const frame = this._readBuffer.subarray(0, this._expected);
            this._readBuffer = this._readBuffer.subarray(this._expected);
            this._expected = null;

            try {
                this._handleFrame(frame);
            } catch (err) {
                this._server.emit('error', err);
            }
        }
    }

    protected _handleFrame(frame: Buffer): void {
        const message = DsoMessage.parse(frame);

        if (message.header.qr !== 0) {
            // Clients don't initiate responses on a Push session.
            // Silently ignore.
            return;
        }

        for (const tlv of message.tlvs) {
            if (tlv instanceof SubscribeTlv) {
                this._handleSubscribe(message.header.id, tlv);
            } else if (tlv instanceof UnsubscribeTlv) {
                this._handleUnsubscribe(tlv);
            } else if (tlv instanceof KeepaliveTlv) {
                this._handleKeepalive(message.header.id, tlv);
            } else if (tlv instanceof ReconfirmTlv) {
                this._server.emit('reconfirm', tlv, this);
            }
            // Unknown TLVs: ignore per RFC 8490 §5.1.2.
        }
    }

    protected _handleSubscribe(messageId: number, tlv: SubscribeTlv): void {
        this.subscriptions.set(messageId, {
            name: tlv.name,
            qtype: tlv.qtype,
            qclass: tlv.qclass,
            messageId: messageId
        });

        this._server._registerSubscription(this);
        this.sendMessage(DsoMessage.response(messageId, 0));
        this._server.emit('subscribe', tlv, this);
    }

    protected _handleUnsubscribe(tlv: UnsubscribeTlv): void {
        this.subscriptions.delete(tlv.originalMessageId);
        this._server._registerSubscription(this); // re-index
        this._server.emit('unsubscribe', tlv, this);
        // UNSUBSCRIBE is unacknowledged — no response.
    }

    protected _handleKeepalive(messageId: number, tlv: KeepaliveTlv): void {
        // Echo our configured window. The smaller of {client request,
        // server policy} wins (RFC 8490 §7.1.1) — caller policy is
        // simpler: just reply with our values.
        const reply = new KeepaliveTlv(this._server.inactivityMs, this._server.keepaliveMs);
        this.sendMessage(DsoMessage.response(messageId, 0, [reply]));
        this._server.emit('keepalive', tlv, this);
    }

    protected _teardown(err?: Error): void {
        if (this._closed) {
            return;
        }

        this._closed = true;
        this.subscriptions.clear();
        this._server._unregisterSession(this);

        if (!this.socket.destroyed) {
            this.socket.destroy();
        }

        this.emit('close', err);
    }

}

/**
 * RFC 8765 DNS Push Notifications server.
 *
 * Listens on a TLS port and accepts long-lived DSO connections.
 * Maintains a per-(name, type, class) registry of subscribers, fanned
 * out by `notify(name, type, records)` to every connection whose
 * subscription matches.
 *
 * Lifecycle:
 *
 *   1. `new PushServer({tls: {cert, key}})` — does NOT bind yet.
 *   2. `await server.listen(port?, host?)` — binds the TLS listener.
 *   3. As clients connect, they're tracked as `PushSession`
 *      instances. The server emits `'connection'`, `'subscribe'`,
 *      `'unsubscribe'`, `'reconfirm'` events for observation.
 *   4. `server.notify(name, type, records)` queues PUSH messages to
 *      every connection with a matching subscription.
 *   5. `await server.close()` ends the listener and closes all
 *      open sessions.
 *
 * Events:
 *
 *   - `'connection'(session: PushSession)` — new TLS connection.
 *   - `'subscribe'(tlv: SubscribeTlv, session: PushSession)` — after
 *     the server has acknowledged the SUBSCRIBE with a NOERROR
 *     response. Useful for logging / quota enforcement.
 *   - `'unsubscribe'(tlv: UnsubscribeTlv, session: PushSession)`.
 *   - `'reconfirm'(tlv: ReconfirmTlv, session: PushSession)` —
 *     RFC 8765 §6.5 leaves the policy to the application. The server
 *     does not auto-respond. Caller decides whether to re-push,
 *     close the session, etc.
 *   - `'error'(err: Error)` — frame parse failures or other I/O
 *     errors. The session that caused it is already gone.
 *
 * Out of scope for v1: rate-limiting, per-subscriber quotas,
 * `RETRY_DELAY` shedding.
 */
export class PushServer extends EventEmitter {

    public readonly inactivityMs: number;
    public readonly keepaliveMs: number;

    protected _options: PushServerOptions;
    protected _server: tls.Server | null;
    protected _sessions: Set<PushSession>;
    protected _index: Map<string, Set<PushSession>>;

    public constructor(options: PushServerOptions) {
        super();

        if (options?.tls === undefined) {
            throw new Error('PushServer: options.tls is required (cert + key)');
        }

        this._options = options;
        this.inactivityMs = options.inactivityMs ?? 1_800_000;
        this.keepaliveMs = options.keepaliveMs ?? 15_000;
        this._server = null;
        this._sessions = new Set();
        this._index = new Map();
    }

    public listen(port: number = 853, host?: string): Promise<void> {
        if (this._server !== null) {
            throw new Error('PushServer: already listening');
        }

        return new Promise<void>((resolve, reject) => {
            const server = tls.createServer(this._options.tls, (socket: tls.TLSSocket): void => {
                const session = new PushSession(this, socket);
                this._sessions.add(session);

                session.on('close', (): void => {
                    this._sessions.delete(session);
                });

                this.emit('connection', session);
            });

            server.once('error', reject);
            server.listen(port, host, (): void => {
                server.removeListener('error', reject);
                this._server = server;
                resolve();
            });
        });
    }

    /**
     * The bound address. Useful in tests where port 0 is passed and
     * the OS picks the actual port.
     */
    public address(): net.AddressInfo | null {
        if (this._server === null) {
            return null;
        }

        const addr = this._server.address();
        return typeof addr === 'string' ? null : addr;
    }

    /**
     * Fan out a PUSH message to every session that subscribed to a
     * matching `(name, qtype, qclass)`. Records' types are matched
     * individually so a notify with multiple types reaches every
     * subscription that covers any of them.
     *
     * `qtype` 255 (ANY) on a subscription matches every record type;
     * a `notify()` cannot use 255 — pass the concrete records you
     * want delivered.
     */
    public notify(records: PacketResource[]): number {
        if (records.length === 0) {
            return 0;
        }

        // Group records into per-session buckets.
        const buckets: Map<PushSession, PacketResource[]> = new Map();

        for (const record of records) {
            const normalizedName = PushServer._normalize(record.name);

            for (const session of this._sessions) {
                for (const sub of session.subscriptions.values()) {
                    if (PushServer._normalize(sub.name) !== normalizedName) {
                        continue;
                    }

                    if (sub.qtype !== 255 && sub.qtype !== record.packetType.type) {
                        continue;
                    }

                    if (sub.qclass !== 255 && sub.qclass !== record.class) {
                        continue;
                    }

                    const list = buckets.get(session);

                    if (list === undefined) {
                        buckets.set(session, [record]);
                    } else if (!list.includes(record)) {
                        list.push(record);
                    }

                    break; // one matching subscription per session is enough
                }
            }
        }

        for (const [session, recs] of buckets.entries()) {
            session.sendMessage(DsoMessage.unilateral(new PushTlv(recs)));
        }

        return buckets.size;
    }

    /**
     * Close the listener and tear down every session.
     */
    public async close(): Promise<void> {
        for (const session of this._sessions) {
            session.close();
        }

        this._sessions.clear();
        this._index.clear();

        if (this._server === null) {
            return;
        }

        const server = this._server;
        this._server = null;

        await new Promise<void>((resolve, reject) => {
            server.close((err): void => {
                if (err !== undefined && err !== null) {
                    reject(err);
                } else {
                    resolve();
                }
            });
        });
    }

    /**
     * Number of active sessions. Useful for tests and metrics.
     */
    public get sessionCount(): number {
        return this._sessions.size;
    }

    /** @internal */
    public _registerSubscription(_session: PushSession): void {
        // Re-indexing per change is a future optimization. The current
        // fan-out walk is O(sessions × subscriptions); fine for the
        // typical "a handful of subscribers" deployment. When that
        // doesn't hold, swap the `_sessions` walk for an index keyed
        // on (name, qtype, qclass).
    }

    /** @internal */
    public _unregisterSession(session: PushSession): void {
        this._sessions.delete(session);
    }

    protected static _normalize(name: string): string {
        const stripped = name.endsWith('.') && name.length > 1 ? name.slice(0, -1) : name;
        return stripped.toLowerCase();
    }

}

export type {PushSession};