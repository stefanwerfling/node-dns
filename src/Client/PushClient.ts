import {Buffer} from 'buffer';
import {EventEmitter} from 'events';
import tls from 'tls';
import {DSO_UNILATERAL_MESSAGE_ID, DsoMessage, KeepaliveTlv, PushTlv, SubscribeTlv, UnsubscribeTlv} from '../Lib/Dso.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';

export type PushClientOptions = {

    /**
     * Hostname or IP of the DNS Push server. Required.
     */
    host: string;

    /**
     * TCP port. Default 853 (DoT / RFC 7858). RFC 8765 §6 reuses the
     * DoT port for Push sessions.
     */
    port?: number;

    /**
     * TLS options forwarded to `tls.connect`. Use `rejectUnauthorized:
     * false` with self-signed certs in tests; in production pass a CA
     * bundle.
     */
    tls?: tls.ConnectionOptions;

    /**
     * How long to wait for the SUBSCRIBE response (RCODE) before
     * rejecting the `subscribe` promise. Default 5000ms.
     */
    requestTimeoutMs?: number;

    /**
     * Inactivity timeout advertised to the server via the initial
     * KEEPALIVE TLV (RFC 8490 §7.1). The server will close the
     * connection if no message flows for this long. Default: 30
     * minutes (1_800_000ms). `0` disables sending the keepalive TLV.
     */
    inactivityMs?: number;

    /**
     * Keepalive interval advertised to the server in the initial
     * KEEPALIVE TLV. The client SHOULD send a `KEEPALIVE` heartbeat
     * within this window when otherwise idle. Default: 15 seconds
     * (15_000ms). Tracked here for completeness; the client doesn't
     * yet send periodic heartbeats automatically — passive presence
     * over TLS is enough for tests and short-lived clients.
     */
    keepaliveMs?: number;
};

/**
 * One active subscription on a `PushClient`. Emits `'push'` for every
 * server-initiated update that names this subscription's
 * `(name, qtype, qclass)`. Also emits `'error'` if the subscription
 * is torn down because the connection closed or the server rejected
 * a later operation.
 *
 * Event signatures:
 *   - `'push'(records: PacketResource[])` — the records that just
 *     changed. RFC 8765 §6.3.1: records with TTL = 0xFFFFFFFF are a
 *     delete signal for the entire RRset; callers can filter on
 *     `r.ttl === 0xFFFFFFFF`. The records are pre-filtered by name +
 *     type/class match against this subscription.
 *   - `'error'(err: Error)` — fatal: subscription is no longer
 *     receiving updates after this fires. Only emitted when a
 *     listener is registered (Node's EventEmitter rule for the
 *     'error' event would otherwise crash the process on close()).
 *   - `'close'(err?: Error)` — always emitted on teardown. Pair with
 *     `'push'` if you want a single signal that the subscription is
 *     done. `err` is `undefined` for clean shutdowns.
 */
export class PushSubscription extends EventEmitter {

    public readonly name: string;
    public readonly qtype: number;
    public readonly qclass: number;
    public readonly messageId: number;

    /** @internal */
    public _active: boolean;

    protected _client: PushClient;

    public constructor(client: PushClient, name: string, qtype: number, qclass: number, messageId: number) {
        super();
        this._client = client;
        this.name = name;
        this.qtype = qtype;
        this.qclass = qclass;
        this.messageId = messageId;
        this._active = true;
    }

    /**
     * Send UNSUBSCRIBE for this subscription and stop receiving
     * updates. Idempotent. Returns once the UNSUBSCRIBE bytes have
     * been written to the socket — UNSUBSCRIBE is unacknowledged
     * (RFC 8765 §6.4).
     */
    public async unsubscribe(): Promise<void> {
        if (!this._active) {
            return;
        }

        this._active = false;
        await this._client._unsubscribe(this);
    }

}

type PendingRequest = {
    resolve: (msg: DsoMessage) => void;
    reject: (err: Error) => void;
    timer: NodeJS.Timeout;
};

/**
 * RFC 8765 DNS Push Notification client. Opens a long-lived TLS
 * connection to a Push-aware server, sends SUBSCRIBE TLVs, and
 * dispatches server-initiated PUSH messages back to the matching
 * `PushSubscription` instances.
 *
 * Multiple concurrent subscriptions share the same TLS connection —
 * each is identified by its 16-bit DSO message ID. Re-subscribing the
 * same `(name, type, class)` is allowed (RFC 8765 §6.1): the server
 * tracks each SUBSCRIBE independently, and each gets its own
 * subscription handle.
 *
 * Lifecycle:
 *
 *   1. `new PushClient({host, port?})` — does NOT connect yet.
 *   2. `await client.subscribe(name, type, cls?)` — connects on
 *      demand, sends KEEPALIVE first (if enabled), then SUBSCRIBE.
 *      Resolves with a `PushSubscription` once the server's RCODE
 *      response arrives.
 *   3. PUSH messages flow asynchronously to the subscription's
 *      `'push'` listeners until either side closes.
 *   4. `await subscription.unsubscribe()` removes a single
 *      subscription; `await client.close()` tears down the
 *      connection and all subscriptions.
 *
 * Out of scope for v1: RECONFIRM, automatic reconnect with
 * `RETRY_DELAY` honoured, periodic KEEPALIVE heartbeats. Callers
 * managing long-lived sessions can layer those on top by watching
 * `'error'` / `'close'`.
 */
export class PushClient extends EventEmitter {

    protected _options: Required<Omit<PushClientOptions, 'tls'>> & {tls: tls.ConnectionOptions};
    protected _socket: tls.TLSSocket | null;
    protected _ready: Promise<void> | null;
    protected _readBuffer: Buffer;
    protected _expected: number | null;
    protected _nextMessageId: number;
    protected _pending: Map<number, PendingRequest>;
    protected _subscriptions: Map<number, PushSubscription>;
    protected _closed: boolean;

    public constructor(options: PushClientOptions) {
        super();

        if (typeof options?.host !== 'string' || options.host.length === 0) {
            throw new Error('PushClient: options.host is required');
        }

        this._options = {
            host: options.host,
            port: options.port ?? 853,
            tls: options.tls ?? {},
            requestTimeoutMs: options.requestTimeoutMs ?? 5_000,
            inactivityMs: options.inactivityMs ?? 1_800_000,
            keepaliveMs: options.keepaliveMs ?? 15_000
        };

        this._socket = null;
        this._ready = null;
        this._readBuffer = Buffer.alloc(0);
        this._expected = null;
        this._nextMessageId = 1; // 0 is reserved for unilateral server messages.
        this._pending = new Map();
        this._subscriptions = new Map();
        this._closed = false;
    }

    /**
     * Subscribe to changes for `(name, qtype, qclass)`. Resolves with
     * a `PushSubscription` once the server has acknowledged the
     * SUBSCRIBE (RCODE = NOERROR). Rejects when the server returns a
     * non-zero RCODE, the request times out, or the connection
     * tears down before the response arrives.
     */
    public async subscribe(
        name: string,
        qtype: PacketTypes | number,
        qclass: PacketClass | number = PacketClass.IN
    ): Promise<PushSubscription> {
        if (this._closed) {
            throw new Error('PushClient: client is closed');
        }

        await this._ensureConnected();

        const messageId = this._allocateMessageId();
        const subscribeTlv = new SubscribeTlv(name, qtype as number, qclass as number);
        const message = DsoMessage.request(messageId, subscribeTlv);

        const responsePromise = this._awaitResponse(messageId);
        this._sendMessage(message);

        const response = await responsePromise;

        if (response.header.rcode !== 0) {
            throw new Error(`PushClient.subscribe: server returned RCODE ${response.header.rcode}`);
        }

        const subscription = new PushSubscription(this, name, qtype as number, qclass as number, messageId);
        this._subscriptions.set(messageId, subscription);
        return subscription;
    }

    /**
     * Close the connection. Pending SUBSCRIBE requests reject; active
     * subscriptions emit `'error'` and `'close'`. Idempotent.
     */
    public async close(): Promise<void> {
        if (this._closed) {
            return;
        }

        this._closed = true;
        this._teardown(new Error('PushClient: connection closed by caller'));
    }

    /**
     * Number of active subscriptions. Decreases on `unsubscribe()` or
     * on connection teardown. Useful for tests and connection-pool
     * accounting.
     */
    public get subscriptionCount(): number {
        return this._subscriptions.size;
    }

    /** @internal */
    public async _unsubscribe(sub: PushSubscription): Promise<void> {
        this._subscriptions.delete(sub.messageId);

        // UNSUBSCRIBE is unacknowledged — no response expected. Use the
        // original SUBSCRIBE message ID per RFC 8765 §6.4.
        if (this._socket === null || this._socket.destroyed) {
            return;
        }

        const message = DsoMessage.request(this._allocateMessageId(), new UnsubscribeTlv(sub.messageId));
        this._sendMessage(message);
    }

    /**
     * Open the TLS connection (lazy). Sends the optional initial
     * KEEPALIVE TLV once `secureConnect` fires so the server knows
     * the inactivity / keepalive window. Resolves when the socket is
     * ready to use.
     *
     * @protected
     */
    protected _ensureConnected(): Promise<void> {
        if (this._ready !== null) {
            return this._ready;
        }

        this._ready = new Promise<void>((resolve, reject) => {
            const connectOptions: tls.ConnectionOptions = {
                host: this._options.host,
                port: this._options.port,
                ...this._options.tls
            };

            const socket = tls.connect(connectOptions);
            this._socket = socket;

            socket.on('data', (chunk: Buffer): void => {
                this._readBuffer = this._readBuffer.length === 0 ? chunk : Buffer.concat([this._readBuffer, chunk]);
                this._drainFrames();
            });

            socket.once('error', (err): void => {
                this._teardown(err);
                reject(err);
            });

            socket.once('close', (): void => {
                this._teardown(new Error('PushClient: connection closed by peer'));
            });

            socket.once('secureConnect', (): void => {
                if (this._options.inactivityMs > 0) {
                    const keepalive = new KeepaliveTlv(this._options.inactivityMs, this._options.keepaliveMs);
                    const message = DsoMessage.request(this._allocateMessageId(), keepalive);
                    // We don't await the response — keepalive is
                    // best-effort and the server may answer
                    // asynchronously. Drop the pending entry after a
                    // short window so it doesn't pin memory.
                    const id = message.header.id;
                    this._sendMessage(message);
                    setTimeout((): void => {
                        const entry = this._pending.get(id);

                        if (entry !== undefined) {
                            clearTimeout(entry.timer);
                            this._pending.delete(id);
                        }
                    }, 1_000).unref?.();
                }

                resolve();
            });
        });

        // Defuse "unhandled rejection" — the caller may not await the
        // very first ensureConnected on every code path.
        this._ready.catch((): void => {
            // no-op
        });

        return this._ready;
    }

    /**
     * Send a `DsoMessage` over the socket with length-prefix framing.
     *
     * @param {DsoMessage} message
     * @protected
     */
    protected _sendMessage(message: DsoMessage): void {
        if (this._socket === null || this._socket.destroyed) {
            throw new Error('PushClient: socket is not connected');
        }

        const body = message.toBuffer();
        const frame = Buffer.alloc(2 + body.length);
        frame.writeUInt16BE(body.length, 0);
        body.copy(frame, 2);
        this._socket.write(frame);
    }

    /**
     * Drain complete length-prefixed frames from `_readBuffer`.
     *
     * @protected
     */
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
                this.emit('error', err);
            }
        }
    }

    /**
     * Route a parsed DSO message to either a pending request (when
     * QR=1 and the ID matches a request we sent) or to the
     * subscription dispatch (when QR=1, ID=0 — unilateral PUSH).
     *
     * @param {Buffer} frame
     * @protected
     */
    protected _handleFrame(frame: Buffer): void {
        const message = DsoMessage.parse(frame);

        if (message.header.qr !== 1) {
            // Servers don't initiate requests on a Push session in
            // this implementation. Silently ignore — RFC 8490 §5.4.
            return;
        }

        if (message.header.id !== DSO_UNILATERAL_MESSAGE_ID) {
            const pending = this._pending.get(message.header.id);

            if (pending !== undefined) {
                clearTimeout(pending.timer);
                this._pending.delete(message.header.id);
                pending.resolve(message);
                return;
            }
            // Response to an unknown request — likely the
            // keepalive ID that already aged out. Drop silently.
            return;
        }

        // Unilateral PUSH from server — dispatch to subscriptions.
        for (const tlv of message.tlvs) {
            if (tlv instanceof PushTlv) {
                this._dispatchPush(tlv);
            }
        }
    }

    /**
     * For each record in `tlv`, fan out to every subscription whose
     * `(name, qtype, qclass)` matches. RFC 8765 §6.3: a subscription
     * with `qtype = ANY` (255) matches any record type for that name.
     *
     * @param {PushTlv} tlv
     * @protected
     */
    protected _dispatchPush(tlv: PushTlv): void {
        // Group records by subscription so each subscription receives
        // one 'push' event per server message, not one per record.
        const buckets: Map<PushSubscription, PacketResource[]> = new Map();

        for (const r of tlv.records) {
            for (const sub of this._subscriptions.values()) {
                if (!PushClient._matches(sub, r)) {
                    continue;
                }

                const list = buckets.get(sub);

                if (list === undefined) {
                    buckets.set(sub, [r]);
                } else {
                    list.push(r);
                }
            }
        }

        for (const [sub, records] of buckets.entries()) {
            try {
                sub.emit('push', records);
            } catch (err) {
                // Don't let a listener's throw kill the dispatch loop.
                this.emit('error', err);
            }
        }
    }

    /**
     * Case-insensitive + trailing-dot tolerant name match. Type
     * matches when the subscription's qtype is ANY (255) or exactly
     * equals the record's type. Class similarly with ANY (255) acting
     * as a wildcard.
     *
     * @param {PushSubscription} sub
     * @param {PacketResource} record
     * @return {boolean}
     * @protected
     */
    protected static _matches(sub: PushSubscription, record: PacketResource): boolean {
        const norm = (n: string): string => {
            const stripped = n.endsWith('.') && n.length > 1 ? n.slice(0, -1) : n;
            return stripped.toLowerCase();
        };

        if (norm(sub.name) !== norm(record.name)) {
            return false;
        }

        const subType = sub.qtype;
        const recType = record.packetType.type;

        // 255 = ANY (RFC 1035 §3.2.3).
        if (subType !== 255 && subType !== recType) {
            return false;
        }

        const subClass = sub.qclass;
        const recClass = record.class;

        if (subClass !== 255 && subClass !== recClass) {
            return false;
        }

        return true;
    }

    /**
     * Reserve the next message ID. Skips 0 (reserved for unilateral
     * server messages) and any ID already pending.
     *
     * @return {number}
     * @protected
     */
    protected _allocateMessageId(): number {
        for (let i = 0; i < 65535; i++) {
            const candidate = this._nextMessageId;
            this._nextMessageId = ((this._nextMessageId + 1) & 0xffff) || 1;

            if (candidate !== DSO_UNILATERAL_MESSAGE_ID && !this._pending.has(candidate) && !this._subscriptions.has(candidate)) {
                return candidate;
            }
        }

        throw new Error('PushClient: exhausted DSO message ID space');
    }

    /**
     * Register a pending request and return a Promise that resolves
     * when the server's response with the matching message ID
     * arrives, or rejects on timeout.
     *
     * @param {number} messageId
     * @return {Promise<DsoMessage>}
     * @protected
     */
    protected _awaitResponse(messageId: number): Promise<DsoMessage> {
        return new Promise<DsoMessage>((resolve, reject) => {
            const timer = setTimeout((): void => {
                this._pending.delete(messageId);
                reject(new Error(`PushClient: request ${messageId} timed out after ${this._options.requestTimeoutMs}ms`));
            }, this._options.requestTimeoutMs);
            timer.unref?.();

            this._pending.set(messageId, {
                resolve: resolve,
                reject: reject,
                timer: timer
            });
        });
    }

    /**
     * Tear everything down: reject pending requests, emit errors on
     * subscriptions, close the socket, fire `'close'`. Idempotent.
     *
     * @param {Error} err
     * @protected
     */
    protected _teardown(err: Error): void {
        for (const pending of this._pending.values()) {
            clearTimeout(pending.timer);
            pending.reject(err);
        }
        this._pending.clear();

        for (const sub of this._subscriptions.values()) {
            sub._active = false;
            // Node throws when 'error' is emitted without a listener,
            // which would crash the process during normal close().
            // Subscribers who care about teardown can register an
            // 'error' listener; otherwise emit 'close' so they have a
            // signal that's safe to ignore.
            if (sub.listenerCount('error') > 0) {
                sub.emit('error', err);
            }
            sub.emit('close', err);
        }
        this._subscriptions.clear();

        if (this._socket !== null && !this._socket.destroyed) {
            this._socket.destroy();
        }

        this._socket = null;
        this._readBuffer = Buffer.alloc(0);
        this._expected = null;
        this._ready = null;

        if (!this._closed) {
            this._closed = true;
        }

        this.emit('close');
    }

}