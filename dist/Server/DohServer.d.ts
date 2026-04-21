import EventEmitter from 'events';
import http from 'http';
import https from 'https';
import { AddressInfo } from 'net';
import { Packet } from '../Packet/Packet.js';
import { ServerOptions } from './ServerOptions.js';
export type DohServerUseCors = (origin: string | undefined) => Promise<boolean>;
export declare class DohServer extends EventEmitter {
    protected _server: http.Server | https.Server;
    protected _cors: boolean | string | DohServerUseCors;
    protected _port: number;
    constructor(options?: ServerOptions | null);
    protected _handleRequest(client: http.IncomingMessage, res: http.ServerResponse): Promise<void>;
    protected _response(res: http.ServerResponse, message: Packet): void;
    listen(port?: number, address?: string): void;
    address(): AddressInfo | string | null;
    close(): void;
    static decodeBase64URL(str: string): string | null;
    static readStream(client: http.IncomingMessage): Promise<string>;
}
