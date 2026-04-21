import dgram from 'dgram';
import http from 'http';
import https from 'https';
import tcp from 'net';
import { Packet } from '../Packet/Packet.js';
import { DohServerUseCors } from './DohServer.js';
import { ServerPreConnection } from './ServerPreConnection.js';
import { ServerPreRequest } from './ServerPreRequest.js';
export type ServerRequestHandler = (request: Packet, send: (response: Packet) => void, client: unknown) => void;
export type ServerUdpOptions = {
    type?: 'udp4' | 'udp6';
    preRequest?: ServerPreRequest<dgram.RemoteInfo>;
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
export type ServerOptions = {
    udp?: boolean | ServerUdpOptions;
    tcp?: boolean | ServerTcpOptions;
    doh?: boolean | ServerDohOptions;
    handle?: ServerRequestHandler;
};
