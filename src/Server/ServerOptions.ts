import dgram from 'dgram';
import http from 'http';
import https from 'https';
import tcp from 'net';
import {Packet} from '../Packet/Packet.js';
import {DohServerUseCors} from './DohServer.js';
import {ServerPreConnection} from './ServerPreConnection.js';
import {ServerPreRequest} from './ServerPreRequest.js';

/**
 * Server request handler
 */
export type ServerRequestHandler = (
    request: Packet,
    send: (response: Packet) => void,
    client: unknown
) => void;

/**
 * UDP transport options
 */
export type ServerUdpOptions = {
    type?: 'udp4' | 'udp6';
    preRequest?: ServerPreRequest<dgram.RemoteInfo>;
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
 * Server options
 */
export type ServerOptions = {
    udp?: boolean | ServerUdpOptions;
    tcp?: boolean | ServerTcpOptions;
    doh?: boolean | ServerDohOptions;
    handle?: ServerRequestHandler;
};