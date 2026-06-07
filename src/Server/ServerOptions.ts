import {Buffer} from 'buffer';
import dgram from 'dgram';
import http from 'http';
import https from 'https';
import tcp from 'net';
import tls from 'tls';
import {Rrl} from '../Lib/Rrl.js';
import {Packet} from '../Packet/Packet.js';
import {DohServerUseCors} from './DohServer.js';
import {ServerPreConnection} from './ServerPreConnection.js';
import {ServerPreRequest} from './ServerPreRequest.js';

/**
 * Server request handler. The `send` callback accepts a single Packet for
 * the typical one-shot response, or `Packet[]` for multi-message exchanges
 * such as AXFR (RFC 5936). UDP only honours the first packet; TCP/TLS write
 * all frames before closing the connection.
 *
 * `rawRequest` carries the post-preRequest wire bytes, the same bytes
 * `Packet.parse` saw. Required for TSIG verification (RFC 8945) — the MAC is
 * bound to specific bytes, and re-encoding the parsed packet may produce a
 * different name-compression layout that no longer matches.
 */
export type ServerRequestHandler = (
    request: Packet,
    send: (response: Packet | Buffer | Array<Packet | Buffer>) => void,
    client: unknown,
    rawRequest: Buffer
) => void;

/**
 * RFC 7873 + RFC 9018 DNS Cookies on the server side. When set,
 * UDPServer validates the EDNS Cookie option on incoming queries and
 * pairs every cookie-carrying response with a refreshed server cookie.
 *
 * Cookies are an inexpensive anti-spoofing layer for UDP: an off-path
 * attacker has no way to learn the server cookie without first
 * receiving a legitimate response, so reflection/amplification floods
 * that omit or forge cookies get a tiny BADCOOKIE response instead of
 * a fully-resolved answer.
 *
 * Combine with `rrl` for defense-in-depth — cookies handle the
 * "haven't seen this client before" case cheaply, RRL handles
 * sustained pressure from any client.
 */
export type ServerCookieOptions = {

    /**
     * HMAC secret used to compute server cookies. At least 16 bytes
     * recommended (RFC 9018 §3.1). Keep this stable across restarts —
     * rotating it invalidates currently-issued cookies and forces an
     * extra round-trip per client to seed a fresh cookie.
     */
    secret: Buffer;

    /**
     * Acceptance policy when an incoming query has *no* cookie option
     * at all:
     *
     *  - `'lenient'` (default) — pass through to the handler verbatim.
     *    Clients that don't support cookies (the legacy `dig` flow,
     *    embedded stacks) still get served. The server will only
     *    issue a server cookie if the client sent at least the
     *    client-cookie half.
     *  - `'strict'` — refuse the query with `REFUSED` and emit
     *    `'cookieRejected'` for metrics.
     *
     * Queries that DO carry a cookie option are always validated —
     * the lenient/strict distinction is only about cookie absence.
     */
    mode?: 'lenient' | 'strict';

    /**
     * Maximum age (seconds) of an accepted server cookie. RFC 9018
     * §4.2 recommends 1h–1d depending on threat model. Default:
     * 3600 (1 hour). `0` disables the age check, accepting any
     * MAC-valid cookie regardless of timestamp.
     */
    maxAgeSeconds?: number;

    /**
     * UDP payload size announced in the BADCOOKIE / REFUSED response's
     * OPT RR (RFC 6891 §6.2.3). Default: 1232 (DNS Flag Day 2020 PMTU-
     * safe). Tune higher if your transport supports it.
     */
    udpPayloadSize?: number;
};

/**
 * UDP transport options
 */
export type ServerUdpOptions = {
    type?: 'udp4' | 'udp6';
    preRequest?: ServerPreRequest<dgram.RemoteInfo>;

    /**
     * Optional Response Rate Limiter. When set, the server consults `rrl.check`
     * for every incoming UDP query and either allows it through, silently
     * drops it, or replies with a TC=1 truncation hint. RRL is meaningful
     * only on UDP — connection-oriented transports do not benefit and should
     * not be wired up here.
     */
    rrl?: Rrl;

    /**
     * Optional DNS Cookie validation (RFC 7873 + RFC 9018). See
     * `ServerCookieOptions`.
     */
    cookies?: ServerCookieOptions;
};

/**
 * TCP transport options
 */
export type ServerTcpOptions = {
    /**
     * Per-message raw buffer processor (runs after the DNS message has been
     * read from the stream, before it is parsed into a Packet).
     */
    preRequest?: ServerPreRequest<tcp.Socket>;

    /**
     * Per-connection processor (runs once per accepted socket, before any
     * DNS data is read). Typical use: PROXY protocol header stripping.
     */
    preConnection?: ServerPreConnection<tcp.Socket>;

    /**
     * Optional DNS Cookie validation (RFC 7873 + RFC 9018). On TCP the
     * cookie is mostly an identity / policy mechanism: a client that
     * fell back from UDP to TCP keeps its existing cookie pair, and a
     * deployment with `mode: 'strict'` rejects cookieless connections
     * consistently across both transports. The handshake already
     * defeats off-path spoofing, so cookies add no extra anti-spoofing
     * value on top.
     */
    cookies?: ServerCookieOptions;
};

/**
 * DoH transport options
 */
export type ServerDohOptions = {
    ssl?: boolean;
    options?: https.ServerOptions;
    cors?: boolean | string | DohServerUseCors;
    preRequest?: ServerPreRequest<http.IncomingMessage>;
};

/**
 * DoT (DNS over TLS, RFC 7858) transport options
 */
export type ServerTlsOptions = {
    /**
     * TLS context options forwarded to `tls.createServer` (cert, key, ca, ...).
     * Required — DoT cannot run without TLS material.
     */
    options: tls.TlsOptions;

    /**
     * Per-message raw buffer processor. Same semantics as `tcp.preRequest`.
     */
    preRequest?: ServerPreRequest<tls.TLSSocket>;

    /**
     * Per-connection processor. Same semantics as `tcp.preConnection`.
     */
    preConnection?: ServerPreConnection<tls.TLSSocket>;

    /**
     * Optional DNS Cookie validation. Same semantics as `tcp.cookies`.
     */
    cookies?: ServerCookieOptions;
};

/**
 * Server options
 */
export type ServerOptions = {
    udp?: boolean | ServerUdpOptions;
    tcp?: boolean | ServerTcpOptions;
    tls?: ServerTlsOptions;
    doh?: boolean | ServerDohOptions;
    handle?: ServerRequestHandler;
};