import { Buffer } from 'buffer';
import dgram from 'dgram';
import http from 'http';
import https from 'https';
import tcp from 'net';
import tls from 'tls';
import { Rrl } from '../Lib/Rrl.js';
import { Packet } from '../Packet/Packet.js';
import { DohServerUseCors } from './DohServer.js';
import { ServerPreConnection } from './ServerPreConnection.js';
import { ServerPreRequest } from './ServerPreRequest.js';
export type ServerRequestHandler = (request: Packet, send: (response: Packet | Buffer | Array<Packet | Buffer>) => void, client: unknown, rawRequest: Buffer) => void;
export type ServerUdpOptions = {
    type?: 'udp4' | 'udp6';
    preRequest?: ServerPreRequest<dgram.RemoteInfo>;
    rrl?: Rrl;
};
export type ServerTcpOptions = {
    preRequest?: ServerPreRequest<tcp.Socket>;
    preConnection?: ServerPreConnection<tcp.Socket>;
};
export type ServerDohOptions = {
    ssl?: boolean;
    options?: https.ServerOptions;
    cors?: boolean | string | DohServerUseCors;
    preRequest?: ServerPreRequest<http.IncomingMessage>;
};
export type ServerTlsOptions = {
    options: tls.TlsOptions;
    preRequest?: ServerPreRequest<tls.TLSSocket>;
    preConnection?: ServerPreConnection<tls.TLSSocket>;
};
export type ServerOptions = {
    udp?: boolean | ServerUdpOptions;
    tcp?: boolean | ServerTcpOptions;
    tls?: ServerTlsOptions;
    doh?: boolean | ServerDohOptions;
    handle?: ServerRequestHandler;
};
