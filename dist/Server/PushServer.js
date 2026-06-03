import { Buffer } from 'buffer';
import { EventEmitter } from 'events';
import tls from 'tls';
import { DsoMessage, KeepaliveTlv, PushTlv, ReconfirmTlv, RetryDelayTlv, SubscribeTlv, UnsubscribeTlv } from '../Lib/Dso.js';
class PushSession extends EventEmitter {
    socket;
    subscriptions;
    _readBuffer;
    _expected;
    _server;
    _closed;
    constructor(server, socket) {
        super();
        this._server = server;
        this.socket = socket;
        this.subscriptions = new Map();
        this._readBuffer = Buffer.alloc(0);
        this._expected = null;
        this._closed = false;
        socket.on('data', (chunk) => {
            this._readBuffer = this._readBuffer.length === 0 ? chunk : Buffer.concat([this._readBuffer, chunk]);
            this._drainFrames();
        });
        socket.once('error', (err) => {
            this._teardown(err);
        });
        socket.once('close', () => {
            this._teardown();
        });
    }
    sendMessage(message) {
        if (this._closed || this.socket.destroyed) {
            return;
        }
        const body = message.toBuffer();
        const frame = Buffer.alloc(2 + body.length);
        frame.writeUInt16BE(body.length, 0);
        body.copy(frame, 2);
        this.socket.write(frame);
    }
    sendRetryDelay(retryDelayMs, closeAfter = false) {
        const message = DsoMessage.unilateral(new RetryDelayTlv(retryDelayMs));
        this.sendMessage(message);
        if (closeAfter) {
            setImmediate(() => this._teardown());
        }
    }
    close() {
        this._teardown();
    }
    get closed() {
        return this._closed;
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
                this._server.emit('error', err);
            }
        }
    }
    _handleFrame(frame) {
        const message = DsoMessage.parse(frame);
        if (message.header.qr !== 0) {
            return;
        }
        for (const tlv of message.tlvs) {
            if (tlv instanceof SubscribeTlv) {
                this._handleSubscribe(message.header.id, tlv);
            }
            else if (tlv instanceof UnsubscribeTlv) {
                this._handleUnsubscribe(tlv);
            }
            else if (tlv instanceof KeepaliveTlv) {
                this._handleKeepalive(message.header.id, tlv);
            }
            else if (tlv instanceof ReconfirmTlv) {
                this._server.emit('reconfirm', tlv, this);
            }
        }
    }
    _handleSubscribe(messageId, tlv) {
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
    _handleUnsubscribe(tlv) {
        this.subscriptions.delete(tlv.originalMessageId);
        this._server._registerSubscription(this);
        this._server.emit('unsubscribe', tlv, this);
    }
    _handleKeepalive(messageId, tlv) {
        const reply = new KeepaliveTlv(this._server.inactivityMs, this._server.keepaliveMs);
        this.sendMessage(DsoMessage.response(messageId, 0, [reply]));
        this._server.emit('keepalive', tlv, this);
    }
    _teardown(err) {
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
export class PushServer extends EventEmitter {
    inactivityMs;
    keepaliveMs;
    _options;
    _server;
    _sessions;
    _index;
    constructor(options) {
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
    listen(port = 853, host) {
        if (this._server !== null) {
            throw new Error('PushServer: already listening');
        }
        return new Promise((resolve, reject) => {
            const server = tls.createServer(this._options.tls, (socket) => {
                const session = new PushSession(this, socket);
                this._sessions.add(session);
                session.on('close', () => {
                    this._sessions.delete(session);
                });
                this.emit('connection', session);
            });
            server.once('error', reject);
            server.listen(port, host, () => {
                server.removeListener('error', reject);
                this._server = server;
                resolve();
            });
        });
    }
    address() {
        if (this._server === null) {
            return null;
        }
        const addr = this._server.address();
        return typeof addr === 'string' ? null : addr;
    }
    notify(records) {
        if (records.length === 0) {
            return 0;
        }
        const buckets = new Map();
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
                    }
                    else if (!list.includes(record)) {
                        list.push(record);
                    }
                    break;
                }
            }
        }
        for (const [session, recs] of buckets.entries()) {
            session.sendMessage(DsoMessage.unilateral(new PushTlv(recs)));
        }
        return buckets.size;
    }
    async close() {
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
        await new Promise((resolve, reject) => {
            server.close((err) => {
                if (err !== undefined && err !== null) {
                    reject(err);
                }
                else {
                    resolve();
                }
            });
        });
    }
    get sessionCount() {
        return this._sessions.size;
    }
    _registerSubscription(_session) {
    }
    _unregisterSession(session) {
        this._sessions.delete(session);
    }
    static _normalize(name) {
        const stripped = name.endsWith('.') && name.length > 1 ? name.slice(0, -1) : name;
        return stripped.toLowerCase();
    }
}
//# sourceMappingURL=PushServer.js.map