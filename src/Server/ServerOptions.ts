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
 */
export type ServerRequestHandler = (
    request: Packet,
    send: (response: Packet | Packet[]) => void,
    client: unknown
) => void;

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