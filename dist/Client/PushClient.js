import { Buffer } from 'buffer';
import { EventEmitter } from 'events';
import tls from 'tls';
import { DSO_UNILATERAL_MESSAGE_ID, DsoMessage, KeepaliveTlv, PushTlv, ReconfirmTlv, RetryDelayTlv, SubscribeTlv, UnsubscribeTlv } from '../Lib/Dso.js';
import { PacketClass } from '../Packet/PacketClass.js';
export class PushSubscription extends EventEmitter {
    name;
    qtype;
    qclass;
    messageId;
    _active;
    _client;
    constructor(client, name, qtype, qclass, messageId) {
        super();
        this._client = client;
        this.name = name;
        this.qtype = qtype;
        this.qclass = qclass;
        this.messageId = messageId;
        this._active = true;
    }
    async unsubscribe() {
        if (!this._active) {
            return;
        }
        this._active = false;
        await this._client._unsubscribe(this);
    }
}
export class PushClient extends EventEmitter {
    _options;
    _socket;
    _ready;
    _readBuffer;
    _expected;
    _nextMessageId;
    _pending;
    _subscriptions;
    _closed;
    _keepaliveTimer;
    _reconnectTimer;
    _pendingRetryDelayMs;
    _reconnectAttempts;
    _reconnecting;
    constructor(options) {
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
            keepaliveMs: options.keepaliveMs ?? 15_000,
            autoReconnect: options.autoReconnect ?? false,
            reconnectDelayMs: options.reconnectDelayMs ?? 1_000,
            maxReconnectAttempts: options.maxReconnectAttempts ?? Infinity
        };
        this._socket = null;
        this._ready = null;
        this._readBuffer = Buffer.alloc(0);
        this._expected = null;
        this._nextMessageId = 1;
        this._pending = new Map();
        this._subscriptions = new Map();
        this._closed = false;
        this._keepaliveTimer = null;
        this._reconnectTimer = null;
        this._pendingRetryDelayMs = null;
        this._reconnectAttempts = 0;
        this._reconnecting = false;
    }
    async subscribe(name, qtype, qclass = PacketClass.IN) {
        if (this._closed) {
            throw new Error('PushClient: client is closed');
        }
        await this._ensureConnected();
        const messageId = this._allocateMessageId();
        const subscribeTlv = new SubscribeTlv(name, qtype, qclass);
        const message = DsoMessage.request(messageId, subscribeTlv);
        const responsePromise = this._awaitResponse(messageId);
        this._sendMessage(message);
        const response = await responsePromise;
        if (response.header.rcode !== 0) {
            throw new Error(`PushClient.subscribe: server returned RCODE ${response.header.rcode}`);
        }
        const subscription = new PushSubscription(this, name, qtype, qclass, messageId);
        this._subscriptions.set(messageId, subscription);
        return subscription;
    }
    async reconfirm(name, qtype, qclass, rdata) {
        if (this._closed) {
            throw new Error('PushClient: client is closed');
        }
        await this._ensureConnected();
        const tlv = new ReconfirmTlv(name, qtype, qclass, rdata);
        const message = DsoMessage.request(this._allocateMessageId(), tlv);
        this._sendMessage(message);
    }
    async close() {
        if (this._closed) {
            return;
        }
        this._closed = true;
        if (this._reconnectTimer !== null) {
            clearTimeout(this._reconnectTimer);
            this._reconnectTimer = null;
        }
        this._reconnecting = false;
        this._teardown(new Error('PushClient: connection closed by caller'));
    }
    get subscriptionCount() {
        return this._subscriptions.size;
    }
    async _unsubscribe(sub) {
        this._subscriptions.delete(sub.messageId);
        if (this._socket === null || this._socket.destroyed) {
            return;
        }
        const message = DsoMessage.request(this._allocateMessageId(), new UnsubscribeTlv(sub.messageId));
        this._sendMessage(message);
    }
    _ensureConnected() {
        if (this._ready !== null) {
            return this._ready;
        }
        this._ready = new Promise((resolve, reject) => {
            const connectOptions = {
                host: this._options.host,
                port: this._options.port,
                ...this._options.tls
            };
            const socket = tls.connect(connectOptions);
            this._socket = socket;
            socket.on('data', (chunk) => {
                this._readBuffer = this._readBuffer.length === 0 ? chunk : Buffer.concat([this._readBuffer, chunk]);
                this._drainFrames();
            });
            socket.once('error', (err) => {
                if (!this._handleConnectionDrop(err)) {
                    reject(err);
                }
            });
            socket.once('close', () => {
                this._handleConnectionDrop(new Error('PushClient: connection closed by peer'));
            });
            socket.once('secureConnect', () => {
                if (this._options.inactivityMs > 0) {
                    const keepalive = new KeepaliveTlv(this._options.inactivityMs, this._options.keepaliveMs);
                    const message = DsoMessage.request(this._allocateMessageId(), keepalive);
                    const id = message.header.id;
                    this._sendMessage(message);
                    setTimeout(() => {
                        const entry = this._pending.get(id);
                        if (entry !== undefined) {
                            clearTimeout(entry.timer);
                            this._pending.delete(id);
                        }
                    }, 1_000).unref?.();
                }
                this._armKeepaliveTimer();
                resolve();
            });
        });
        this._ready.catch(() => {
        });
        return this._ready;
    }
    _handleConnectionDrop(err) {
        if (this._closed || this._reconnecting) {
            this._clearKeepaliveTimer();
            return false;
        }
        if (this._options.autoReconnect && this._subscriptions.size > 0) {
            this._clearKeepaliveTimer();
            this._scheduleReconnect();
            return true;
        }
        this._teardown(err);
        return false;
    }
    _scheduleReconnect() {
        if (this._reconnectAttempts >= this._options.maxReconnectAttempts) {
            this.emit('reconnectFailed', new Error(`PushClient: gave up after ${this._reconnectAttempts} reconnect attempts`));
            this._teardown(new Error('PushClient: reconnect attempts exhausted'));
            return;
        }
        this._socket = null;
        this._ready = null;
        this._readBuffer = Buffer.alloc(0);
        this._expected = null;
        this._reconnecting = true;
        const delay = this._pendingRetryDelayMs ?? this._options.reconnectDelayMs;
        this._pendingRetryDelayMs = null;
        this._reconnectAttempts++;
        this._reconnectTimer = setTimeout(() => {
            this._reconnectTimer = null;
            void this._doReconnect();
        }, delay);
        this._reconnectTimer.unref?.();
    }
    async _doReconnect() {
        try {
            await this._ensureConnected();
            const subs = Array.from(this._subscriptions.values());
            this._subscriptions.clear();
            for (const sub of subs) {
                if (!sub._active) {
                    continue;
                }
                const newId = this._allocateMessageId();
                const subscribeTlv = new SubscribeTlv(sub.name, sub.qtype, sub.qclass);
                const message = DsoMessage.request(newId, subscribeTlv);
                const responsePromise = this._awaitResponse(newId);
                this._sendMessage(message);
                const response = await responsePromise;
                if (response.header.rcode !== 0) {
                    throw new Error(`PushClient.reconnect: server rejected re-SUBSCRIBE (rcode ${response.header.rcode})`);
                }
                sub.messageId = newId;
                this._subscriptions.set(newId, sub);
            }
            this._reconnecting = false;
            this._reconnectAttempts = 0;
            this.emit('reconnect');
        }
        catch (err) {
            this._reconnecting = false;
            this._scheduleReconnect();
            this.emit('error', err);
        }
    }
    _armKeepaliveTimer() {
        this._clearKeepaliveTimer();
        if (this._options.keepaliveMs <= 0) {
            return;
        }
        this._keepaliveTimer = setTimeout(() => {
            this._keepaliveTimer = null;
            this._sendHeartbeat();
        }, this._options.keepaliveMs);
        this._keepaliveTimer.unref?.();
    }
    _clearKeepaliveTimer() {
        if (this._keepaliveTimer !== null) {
            clearTimeout(this._keepaliveTimer);
            this._keepaliveTimer = null;
        }
    }
    _sendHeartbeat() {
        if (this._socket === null || this._socket.destroyed) {
            return;
        }
        try {
            const keepalive = new KeepaliveTlv(this._options.inactivityMs, this._options.keepaliveMs);
            const message = DsoMessage.request(this._allocateMessageId(), keepalive);
            this._sendMessage(message);
        }
        catch {
        }
    }
    _sendMessage(message) {
        if (this._socket === null || this._socket.destroyed) {
            throw new Error('PushClient: socket is not connected');
        }
        const body = message.toBuffer();
        const frame = Buffer.alloc(2 + body.length);
        frame.writeUInt16BE(body.length, 0);
        body.copy(frame, 2);
        this._socket.write(frame);
        this._armKeepaliveTimer();
    }
    _drainFrames() {
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
            }
            catch (err) {
                this.emit('error', err);
            }
        }
    }
    _handleFrame(frame) {
        const message = DsoMessage.parse(frame);
        if (message.header.qr !== 1) {
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
            return;
        }
        for (const tlv of message.tlvs) {
            if (tlv instanceof PushTlv) {
                this._dispatchPush(tlv);
            }
            else if (tlv instanceof RetryDelayTlv) {
                this._handleRetryDelay(tlv);
            }
        }
    }
    _handleRetryDelay(tlv) {
        this._pendingRetryDelayMs = tlv.retryDelayMs;
        this.emit('retryDelay', tlv.retryDelayMs);
    }
    _dispatchPush(tlv) {
        const buckets = new Map();
        for (const r of tlv.records) {
            for (const sub of this._subscriptions.values()) {
                if (!PushClient._matches(sub, r)) {
                    continue;
                }
                const list = buckets.get(sub);
                if (list === undefined) {
                    buckets.set(sub, [r]);
                }
                else {
                    list.push(r);
                }
            }
        }
        for (const [sub, records] of buckets.entries()) {
            try {
                sub.emit('push', records);
            }
            catch (err) {
                this.emit('error', err);
            }
        }
    }
    static _matches(sub, record) {
        const norm = (n) => {
            const stripped = n.endsWith('.') && n.length > 1 ? n.slice(0, -1) : n;
            return stripped.toLowerCase();
        };
        if (norm(sub.name) !== norm(record.name)) {
            return false;
        }
        const subType = sub.qtype;
        const recType = record.packetType.type;
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
    _allocateMessageId() {
        for (let i = 0; i < 65535; i++) {
            const candidate = this._nextMessageId;
            this._nextMessageId = ((this._nextMessageId + 1) & 0xffff) || 1;
            if (candidate !== DSO_UNILATERAL_MESSAGE_ID && !this._pending.has(candidate) && !this._subscriptions.has(candidate)) {
                return candidate;
            }
        }
        throw new Error('PushClient: exhausted DSO message ID space');
    }
    _awaitResponse(messageId) {
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
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
    _teardown(err) {
        this._clearKeepaliveTimer();
        if (this._reconnectTimer !== null) {
            clearTimeout(this._reconnectTimer);
            this._reconnectTimer = null;
        }
        for (const pending of this._pending.values()) {
            clearTimeout(pending.timer);
            pending.reject(err);
        }
        this._pending.clear();
        for (const sub of this._subscriptions.values()) {
            sub._active = false;
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
//# sourceMappingURL=PushClient.js.map