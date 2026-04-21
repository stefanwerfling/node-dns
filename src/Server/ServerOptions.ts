import https from 'https';
import {Packet} from '../Packet/Packet.js';
import {DohServerUseCors} from './DohServer.js';

/**
 * Server request handler
 */
export type ServerRequestHandler = (
    request: Packet,
    send: (response: Packet) => void,
    client: unknown
) => void;

/**
 * Server options
 */
export type ServerOptions = {
    udp?: boolean | {
        type?: 'udp4' | 'udp6';
    };
    tcp?: boolean | object;
    doh?: boolean | {
        ssl?: boolean;
        options?: https.ServerOptions;
        cors?: boolean | string | DohServerUseCors;
    };
    handle?: ServerRequestHandler;
};