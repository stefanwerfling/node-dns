import { Buffer } from 'buffer';
import tcp from 'net';
import { Packet } from '../Packet/Packet.js';
import { ServerOptions } from './ServerOptions.js';
import { ServerPreConnection } from './ServerPreConnection.js';
import { ServerPreRequest } from './ServerPreRequest.js';
export type TCPSendable = Packet | Buffer | Array<Packet | Buffer>;
export type TCPServerEvents = {
    request: (msgRequest: Packet, send: (response: TCPSendable) => void, client: tcp.Socket, rawRequest: Buffer) => void;
    requestError: (error: Error) => void;
    listening: () => void;
    close: () => void;
};
export declare class TCPServer {
    protected _tcpServer: tcp.Server;
    protected _options: ServerOptions | null;
    protected _preRequest?: ServerPreRequest<tcp.Socket>;
    protected _preConnection?: ServerPreConnection<tcp.Socket>;
    constructor(options?: ServerOptions | null);
    protected _loadHooks(): void;
    protected _createInternalServer(listener: (socket: tcp.Socket) => void): tcp.Server;
    listen(...args: Parameters<tcp.Server['listen']>): this;
    close(callback?: (err?: Error) => void): void;
    on<K extends keyof TCPServerEvents>(event: K, listener: TCPServerEvents[K]): this;
    once<K extends keyof TCPServerEvents>(event: K, listener: TCPServerEvents[K]): this;
    protected _handle(client: tcp.Socket): Promise<void>;
    protected _response(client: tcp.Socket, message: TCPSendable): void;
    address(): tcp.AddressInfo | string | null;
}
