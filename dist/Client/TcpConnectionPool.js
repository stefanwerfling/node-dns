import { Buffer } from 'buffer';
import tcp from 'net';
import tls from 'tls';
import { Packet } from '../Packet/Packet.js';
import { AClient } from './AClient.js';
class PooledConnection {
    _socket;
    _ready;
    _readyResolve = null;
    _readyReject = null;
    _connectTimer = null;
    _readBuffer = Buffer.alloc(0);
    _expected = null;
    _pending = new Map();
    _nextId = 0;
    _idleTimer = null;
    _queryCount = 0;
    _destroyed = false;
    _onDestroy;
    _options;
    constructor(target, options, onDestroy) {
        this._options = options;
        this._onDestroy = onDestroy;
        this._nextId = (Math.random() * 0xFFFF) | 0;
        this._ready = new Promise((resolve, reject) => {
            this._readyResolve = resolve;
            this._readyReject = reject;
        });
        this._ready.catch(() => undefined);
        this._socket = this._openSocket(target);
        this._wireSocket(this._socket);
    }
    query(message) {
        if (this._destroyed) {
            return Promise.reject(new Error('TcpConnectionPool: connection destroyed'));
        }
        if (message.length < 12) {
            return Promise.reject(new Error('TcpConnectionPool: query too short to be a DNS message'));
        }
        const internalId = this._allocateId();
        if (internalId === null) {
            return Promise.reject(new Error('TcpConnectionPool: connection out of free IDs (65536 in flight?)'));
        }
        const originalId = message.readUInt16BE(0);
        const out = Buffer.from(message);
        out.writeUInt16BE(internalId, 0);
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                const entry = this._pending.get(internalId);
                if (entry !== undefined) {
                    this._pending.delete(internalId);
                    entry.reject(new Error('TcpConnectionPool: query timeout'));
                    this._maybeStartIdleTimer();
                }
            }, this._options.queryTimeoutMs);
            const entry = {
                originalId: originalId,
                resolve: resolve,
                reject: reject,
                timer: timer
            };
            this._pending.set(internalId, entry);
            this._cancelIdleTimer();
            this._queryCount++;
            this._ready.then(() => {
                if (this._destroyed) {
                    return;
                }
                if (this._socket === null) {
                    return;
                }
                const len = Buffer.alloc(2);
                len.writeUInt16BE(out.length, 0);
                this._socket.write(Buffer.concat([len, out]));
            }).catch((err) => {
                const pending = this._pending.get(internalId);
                if (pending !== undefined) {
                    this._pending.delete(internalId);
                    clearTimeout(pending.timer);
                    pending.reject(err instanceof Error ? err : new Error(String(err)));
                }
            });
        });
    }
    hasCapacity() {
        if (this._destroyed) {
            return false;
        }
        if (this._options.maxQueriesPerConnection === 0) {
            return true;
        }
        return this._queryCount < this._options.maxQueriesPerConnection;
    }
    isIdle() {
        return this._pending.size === 0;
    }
    destroy(reason) {
        if (this._destroyed) {
            return;
        }
        this._destroyed = true;
        if (this._connectTimer !== null) {
            clearTimeout(this._connectTimer);
            this._connectTimer = null;
        }
        this._cancelIdleTimer();
        const err = reason ?? new Error('TcpConnectionPool: connection closed');
        for (const [, entry] of this._pending) {
            clearTimeout(entry.timer);
            entry.reject(err);
        }
        this._pending.clear();
        if (this._readyReject !== null) {
            const rej = this._readyReject;
            this._readyReject = null;
            this._readyResolve = null;
            rej(err);
        }
        if (this._socket !== null) {
            try {
                this._socket.destroy();
            }
            catch {
            }
            this._socket = null;
        }
        const cb = this._onDestroy;
        this._onDestroy = null;
        if (cb !== null) {
            cb();
        }
    }
    _openSocket(target) {
        if (target.protocol === 'tls') {
            const tlsOpts = {
                host: target.host,
                port: target.port,
                servername: target.host,
                ...target.tlsOptions
            };
            return tls.connect(tlsOpts);
        }
        return tcp.createConnection({ host: target.host, port: target.port });
    }
    _wireSocket(socket) {
        const onReady = () => {
            if (this._connectTimer !== null) {
                clearTimeout(this._connectTimer);
                this._connectTimer = null;
            }
            if (this._readyResolve !== null) {
                const resolve = this._readyResolve;
                this._readyResolve = null;
                this._readyReject = null;
                resolve();
            }
            this._maybeStartIdleTimer();
        };
        if (socket instanceof tls.TLSSocket) {
            socket.once('secureConnect', onReady);
        }
        else {
            socket.once('connect', onReady);
        }
        socket.on('data', (chunk) => {
            this._readBuffer = this._readBuffer.length === 0 ? chunk : Buffer.concat([this._readBuffer, chunk]);
            this._drainFrames();
        });
        const onTeardown = (err) => {
            if (this._destroyed) {
                return;
            }
            const reason = err ?? new Error('TcpConnectionPool: connection closed by peer');
            this.destroy(reason);
        };
        socket.once('error', (err) => onTeardown(err));
        socket.once('close', () => onTeardown());
        this._connectTimer = setTimeout(() => {
            this.destroy(new Error('TcpConnectionPool: connect timeout'));
        }, this._options.connectTimeoutMs);
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
            this._handleFrame(frame);
        }
    }
    _handleFrame(frame) {
        if (frame.length < 2) {
            this.destroy(new Error('TcpConnectionPool: undersized response frame'));
            return;
        }
        const internalId = frame.readUInt16BE(0);
        const entry = this._pending.get(internalId);
        if (entry === undefined) {
            return;
        }
        this._pending.delete(internalId);
        clearTimeout(entry.timer);
        const restored = Buffer.from(frame);
        restored.writeUInt16BE(entry.originalId, 0);
        try {
            entry.resolve(restored);
        }
        finally {
            this._maybeStartIdleTimer();
            if (!this.hasCapacity() && this.isIdle()) {
                this.destroy();
            }
        }
    }
    _allocateId() {
        for (let i = 0; i < 0x10000; i++) {
            const candidate = (this._nextId + i) & 0xFFFF;
            if (!this._pending.has(candidate)) {
                this._nextId = (candidate + 1) & 0xFFFF;
                return candidate;
            }
        }
        return null;
    }
    _maybeStartIdleTimer() {
        if (this._destroyed) {
            return;
        }
        if (!this.isIdle()) {
            return;
        }
        if (this._options.idleTimeoutMs <= 0) {
            return;
        }
        this._cancelIdleTimer();
        this._idleTimer = setTimeout(() => {
            this._idleTimer = null;
            this.destroy();
        }, this._options.idleTimeoutMs);
        if (typeof this._idleTimer.unref === 'function') {
            this._idleTimer.unref();
        }
    }
    _cancelIdleTimer() {
        if (this._idleTimer !== null) {
            clearTimeout(this._idleTimer);
            this._idleTimer = null;
        }
    }
}
export class TcpConnectionPool extends AClient {
    _connections = new Map();
    _options;
    _closed = false;
    constructor(options = {}) {
        super();
        this._options = {
            idleTimeoutMs: options.idleTimeoutMs ?? 10000,
            queryTimeoutMs: options.queryTimeoutMs ?? 5000,
            connectTimeoutMs: options.connectTimeoutMs ?? 5000,
            maxQueriesPerConnection: options.maxQueriesPerConnection ?? 0
        };
    }
    send(target, message) {
        if (this._closed) {
            return Promise.reject(new Error('TcpConnectionPool: pool is closed'));
        }
        if (message.length < 12) {
            return Promise.reject(new Error('TcpConnectionPool: query too short to be a DNS message'));
        }
        const conn = this._acquire(target);
        return conn.query(message);
    }
    asResolverTransport(defaults = {}) {
        const protocol = defaults.protocol ?? 'tcp';
        const tlsOptions = defaults.tlsOptions;
        return async (serverIp, port, query) => {
            const target = {
                protocol: protocol,
                host: serverIp,
                port: port,
                tlsOptions: tlsOptions
            };
            const responseBytes = await this.send(target, query.toBuffer());
            return Packet.parse(responseBytes);
        };
    }
    close() {
        if (this._closed) {
            return;
        }
        this._closed = true;
        for (const conn of this._connections.values()) {
            conn.destroy(new Error('TcpConnectionPool: pool closed'));
        }
        this._connections.clear();
    }
    size() {
        return this._connections.size;
    }
    _acquire(target) {
        const key = TcpConnectionPool._keyFor(target);
        const existing = this._connections.get(key);
        if (existing !== undefined && existing.hasCapacity()) {
            return existing;
        }
        const conn = new PooledConnection(target, this._options, () => {
            if (this._connections.get(key) === conn) {
                this._connections.delete(key);
            }
        });
        if (existing !== undefined) {
        }
        this._connections.set(key, conn);
        return conn;
    }
    static _keyFor(target) {
        return `${target.protocol}|${target.host}|${target.port}`;
    }
}
//# sourceMappingURL=TcpConnectionPool.js.map