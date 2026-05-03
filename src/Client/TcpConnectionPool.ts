import {Buffer} from 'buffer';
import tcp from 'net';
import tls from 'tls';
import {Packet} from '../Packet/Packet.js';
import type {RecursiveResolverTransport} from '../Resolver/RecursiveResolver.js';
import {AClient} from './AClient.js';

/**
 * Transport selector for a pool target. `tcp` opens a plain TCP
 * socket; `tls` performs a TLS handshake (DoT, RFC 7858). The pool
 * keeps separate connections for each protocol/host/port triple even
 * when the host:port pair is identical — the wire framing is the same
 * but the connection is not interchangeable.
 */
export type TcpConnectionPoolProtocol = 'tcp' | 'tls';

/**
 * One reachable upstream. Equivalent targets are deduplicated to a
 * single open connection by the pool.
 */
export type TcpConnectionPoolTarget = {
    protocol: TcpConnectionPoolProtocol;
    host: string;
    port: number;

    /**
     * Optional TLS-specific knobs forwarded to `tls.connect`.
     * Ignored when `protocol === 'tcp'`. `servername` defaults to
     * `host` if omitted; pass `rejectUnauthorized: false` to skip
     * chain validation against self-signed certs (test setups).
     */
    tlsOptions?: tls.ConnectionOptions;
};

/**
 * Defaults applied when `asResolverTransport()` builds a
 * `RecursiveResolverTransport`. The resolver hands in `(ip, port,
 * query)` per call, and the adapter combines those with these
 * defaults to form a full `TcpConnectionPoolTarget`.
 */
export type TcpConnectionPoolTransportDefaults = {
    protocol?: TcpConnectionPoolProtocol;
    tlsOptions?: tls.ConnectionOptions;
};

export type TcpConnectionPoolOptions = {
    /**
     * Close an idle connection after this many milliseconds with no
     * in-flight queries. Default 10000 — RFC 7766 §6.2.4 floor for
     * resolvers; tune up if you expect bursty traffic. Pass `0` to
     * never auto-close (you must `pool.close()` explicitly then).
     */
    idleTimeoutMs?: number;

    /**
     * Reject a query if no response arrives within this many
     * milliseconds. Default 5000.
     */
    queryTimeoutMs?: number;

    /**
     * Reject a connect attempt if the socket isn't ready within this
     * many milliseconds. Default 5000.
     */
    connectTimeoutMs?: number;

    /**
     * Force-rotate the connection after this many queries (counting
     * any cancelled ones). `0` (default) disables rotation — the
     * connection stays open until idle timeout or error.
     */
    maxQueriesPerConnection?: number;
};

type ResolvedPoolOptions = {
    idleTimeoutMs: number;
    queryTimeoutMs: number;
    connectTimeoutMs: number;
    maxQueriesPerConnection: number;
};

type PendingQuery = {
    originalId: number;
    resolve: (msg: Buffer) => void;
    reject: (err: Error) => void;
    timer: NodeJS.Timeout;
};

/**
 * Reusable TCP/TLS connection for the DNS length-prefix framing
 * (RFC 7766 §8). One instance per `(protocol, host, port)` triple
 * inside the pool. Multiplexes pipelined queries by rewriting the
 * 16-bit DNS header ID to a pool-internal one before sending and
 * restoring it on the response — RFC 7766 §6.2.1.1 explicitly
 * permits out-of-order responses, so the pool must dispatch by ID
 * not arrival order.
 *
 * The connection is owned by `TcpConnectionPool` and never handed
 * out to callers — keeping framing and ID bookkeeping inside the
 * class avoids consumers tripping over either.
 */
class PooledConnection {

    private _socket: tcp.Socket | tls.TLSSocket | null;
    private _ready: Promise<void>;
    private _readyResolve: (() => void) | null = null;
    private _readyReject: ((err: Error) => void) | null = null;
    private _connectTimer: NodeJS.Timeout | null = null;
    private _readBuffer: Buffer = Buffer.alloc(0);
    private _expected: number | null = null;
    private readonly _pending: Map<number, PendingQuery> = new Map();
    private _nextId: number = 0;
    private _idleTimer: NodeJS.Timeout | null = null;
    private _queryCount: number = 0;
    private _destroyed: boolean = false;
    private _onDestroy: (() => void) | null;
    private readonly _options: ResolvedPoolOptions;

    public constructor(target: TcpConnectionPoolTarget, options: ResolvedPoolOptions, onDestroy: () => void) {
        this._options = options;
        this._onDestroy = onDestroy;

        // Seed the random starting point so the first ID isn't always
        // zero — defends against a passive observer correlating queries
        // when the pool first opens.
        // eslint-disable-next-line no-bitwise
        this._nextId = (Math.random() * 0xFFFF) | 0;

        this._ready = new Promise<void>((resolve, reject) => {
            this._readyResolve = resolve;
            this._readyReject = reject;
        });

        // Mark `_ready` as handled at construction time. Each `query()` call
        // attaches its own `.then().catch(...)` chain, but a connection that
        // is destroyed before the first query (e.g. pool.close() while idle
        // or input validation rejects synchronously) would otherwise leak
        // an unhandled rejection.
        this._ready.catch(() => undefined);

        this._socket = this._openSocket(target);
        this._wireSocket(this._socket);
    }

    /**
     * Send `message` (a complete DNS packet, no length prefix) and
     * resolve with the response bytes whose DNS header ID matches.
     * Pipelined-safe: callers may have multiple in-flight queries on
     * the same connection.
     */
    public query(message: Buffer): Promise<Buffer> {
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

        return new Promise<Buffer>((resolve, reject) => {
            const timer = setTimeout(() => {
                const entry = this._pending.get(internalId);

                if (entry !== undefined) {
                    this._pending.delete(internalId);
                    entry.reject(new Error('TcpConnectionPool: query timeout'));
                    this._maybeStartIdleTimer();
                }
            }, this._options.queryTimeoutMs);

            const entry: PendingQuery = {
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

    public hasCapacity(): boolean {
        if (this._destroyed) {
            return false;
        }

        if (this._options.maxQueriesPerConnection === 0) {
            return true;
        }

        return this._queryCount < this._options.maxQueriesPerConnection;
    }

    public isIdle(): boolean {
        return this._pending.size === 0;
    }

    public destroy(reason?: Error): void {
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
            // Surface a connect failure to anyone still waiting on _ready.
            // No-op if _ready has already resolved.
            const rej = this._readyReject;
            this._readyReject = null;
            this._readyResolve = null;
            rej(err);
        }

        if (this._socket !== null) {
            try {
                this._socket.destroy();
            } catch {
                /* socket may already be torn down */
            }

            this._socket = null;
        }

        const cb = this._onDestroy;
        this._onDestroy = null;

        if (cb !== null) {
            cb();
        }
    }

    private _openSocket(target: TcpConnectionPoolTarget): tcp.Socket | tls.TLSSocket {
        if (target.protocol === 'tls') {
            const tlsOpts: tls.ConnectionOptions = {
                host: target.host,
                port: target.port,
                servername: target.host,
                ...target.tlsOptions
            };
            return tls.connect(tlsOpts);
        }

        return tcp.createConnection({host: target.host, port: target.port});
    }

    private _wireSocket(socket: tcp.Socket | tls.TLSSocket): void {
        const onReady = (): void => {
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
        } else {
            socket.once('connect', onReady);
        }

        socket.on('data', (chunk: Buffer) => {
            this._readBuffer = this._readBuffer.length === 0 ? chunk : Buffer.concat([this._readBuffer, chunk]);
            this._drainFrames();
        });

        const onTeardown = (err?: Error): void => {
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

    private _drainFrames(): void {
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

    private _handleFrame(frame: Buffer): void {
        if (frame.length < 2) {
            // Malformed frame — closest peers tend to drop the connection.
            this.destroy(new Error('TcpConnectionPool: undersized response frame'));
            return;
        }

        const internalId = frame.readUInt16BE(0);
        const entry = this._pending.get(internalId);

        if (entry === undefined) {
            // Unknown ID — could be a delayed response after timeout, or
            // a server bug. Drop silently rather than tearing down the
            // connection: legitimate queries on the same socket still work.
            return;
        }

        this._pending.delete(internalId);
        clearTimeout(entry.timer);

        // Restore the caller's original DNS ID so the response matches
        // their request from their perspective. Copy first to keep the
        // socket buffer untouched.
        const restored = Buffer.from(frame);
        restored.writeUInt16BE(entry.originalId, 0);

        try {
            entry.resolve(restored);
        } finally {
            this._maybeStartIdleTimer();

            if (!this.hasCapacity() && this.isIdle()) {
                this.destroy();
            }
        }
    }

    private _allocateId(): number | null {
        for (let i = 0; i < 0x10000; i++) {
            // eslint-disable-next-line no-bitwise
            const candidate = (this._nextId + i) & 0xFFFF;

            if (!this._pending.has(candidate)) {
                // eslint-disable-next-line no-bitwise
                this._nextId = (candidate + 1) & 0xFFFF;
                return candidate;
            }
        }

        return null;
    }

    private _maybeStartIdleTimer(): void {
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

        // Don't pin the event loop on idle pool entries — a process
        // that's otherwise quiet should be allowed to exit.
        if (typeof this._idleTimer.unref === 'function') {
            this._idleTimer.unref();
        }
    }

    private _cancelIdleTimer(): void {
        if (this._idleTimer !== null) {
            clearTimeout(this._idleTimer);
            this._idleTimer = null;
        }
    }

}

/**
 * RFC 7766 §6.2 connection pool for TCP/TLS DNS. Reuses a single
 * persistent socket per `(protocol, host, port)` target across
 * pipelined queries. Plays the DNS-Cookies / 0x20 game by leaving
 * payloads untouched and only rewriting the 16-bit transaction ID
 * for response correlation.
 *
 * Lifecycle:
 *   const pool = new TcpConnectionPool({idleTimeoutMs: 30000});
 *   const responseBytes = await pool.send({protocol: 'tcp', host, port}, queryBytes);
 *   pool.close(); // tear down all live sockets
 *
 * The pool isn't pre-allocated. Connections open on first use and
 * close after `idleTimeoutMs` of no in-flight queries. Errored or
 * peer-closed connections are dropped immediately and re-opened on
 * the next `send()` for the same target — callers see only the
 * single failed query reject, subsequent queries succeed.
 *
 * Out of scope (v1):
 *  - Multiple concurrent connections to the same target — DNS-over-
 *    TCP servers are required to accept pipelined queries on a single
 *    connection (RFC 7766 §6.2.1.1), so the simpler design suffices.
 *  - AXFR / IXFR-fallback-to-AXFR — those use connection-end as the
 *    termination signal, which is incompatible with multiplexing.
 *    Keep using `AxfrClient` directly for zone transfers.
 */
export class TcpConnectionPool extends AClient {

    private readonly _connections: Map<string, PooledConnection> = new Map();
    private readonly _options: ResolvedPoolOptions;
    private _closed: boolean = false;

    public constructor(options: TcpConnectionPoolOptions = {}) {
        super();

        this._options = {
            idleTimeoutMs: options.idleTimeoutMs ?? 10000,
            queryTimeoutMs: options.queryTimeoutMs ?? 5000,
            connectTimeoutMs: options.connectTimeoutMs ?? 5000,
            maxQueriesPerConnection: options.maxQueriesPerConnection ?? 0
        };
    }

    /**
     * Send `message` (a complete DNS packet, no length prefix) over a
     * pooled connection and return the matching response bytes. The
     * caller-side DNS header ID is preserved on the returned buffer
     * even though the wire ID is rewritten internally.
     */
    public send(target: TcpConnectionPoolTarget, message: Buffer): Promise<Buffer> {
        if (this._closed) {
            return Promise.reject(new Error('TcpConnectionPool: pool is closed'));
        }

        if (message.length < 12) {
            // Reject before opening a socket — saves a TCP handshake on a
            // query that can't possibly be valid DNS anyway.
            return Promise.reject(new Error('TcpConnectionPool: query too short to be a DNS message'));
        }

        const conn = this._acquire(target);
        return conn.query(message);
    }

    /**
     * Convenience adapter for `RecursiveResolver`. The returned
     * function fits `RecursiveResolverTransport` and routes every
     * query through this pool — drop it into the resolver's
     * `tcpTransport` option to wrap the TC=1 fallback path in pooling.
     *
     * `protocol` defaults to `'tcp'`; pass `'tls'` to send DoT.
     */
    public asResolverTransport(defaults: TcpConnectionPoolTransportDefaults = {}): RecursiveResolverTransport {
        const protocol: TcpConnectionPoolProtocol = defaults.protocol ?? 'tcp';
        const tlsOptions = defaults.tlsOptions;

        return async(serverIp: string, port: number, query: Packet): Promise<Packet> => {
            const target: TcpConnectionPoolTarget = {
                protocol: protocol,
                host: serverIp,
                port: port,
                tlsOptions: tlsOptions
            };

            const responseBytes = await this.send(target, query.toBuffer());
            return Packet.parse(responseBytes);
        };
    }

    /**
     * Tear down every open connection. Pending queries reject with a
     * "pool closed" error. Once closed, the pool can't be reused —
     * create a new instance.
     */
    public close(): void {
        if (this._closed) {
            return;
        }

        this._closed = true;

        for (const conn of this._connections.values()) {
            conn.destroy(new Error('TcpConnectionPool: pool closed'));
        }

        this._connections.clear();
    }

    /**
     * Snapshot count of live connections — primarily for tests and
     * metrics. Includes connections that are in the middle of opening.
     */
    public size(): number {
        return this._connections.size;
    }

    private _acquire(target: TcpConnectionPoolTarget): PooledConnection {
        const key = TcpConnectionPool._keyFor(target);
        const existing = this._connections.get(key);

        if (existing !== undefined && existing.hasCapacity()) {
            return existing;
        }

        const conn = new PooledConnection(target, this._options, () => {
            // Only drop the entry if it still points at this connection —
            // a fresh one may have already taken its slot in the map.
            if (this._connections.get(key) === conn) {
                this._connections.delete(key);
            }
        });

        if (existing !== undefined) {
            // Replaced because the old one was at-capacity but not yet
            // destroyed (pending tail of queries on the old one finishes
            // out). Don't tear it down here — let it close itself when
            // the in-flight queries drain.
        }

        this._connections.set(key, conn);
        return conn;
    }

    private static _keyFor(target: TcpConnectionPoolTarget): string {
        return `${target.protocol}|${target.host}|${target.port}`;
    }

}