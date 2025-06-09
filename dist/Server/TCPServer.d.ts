import tcp from 'net';
import { Packet } from '../Packet/Packet.js';
import { ServerOptions } from './ServerOptions.js';
export type TCPServerEvents = {
    request: (msgRequest: Packet, send: (request: Packet) => void, client: tcp.Socket) => void;
    requestError: (error: Error) => void;
};
export declare class TCPServer extends tcp.Server {
    protected _options: ServerOptions | null;
    constructor(options?: ServerOptions | null);
    on<K extends keyof TCPServerEvents>(event: K, listener: TCPServerEvents[K]): this;
    once<K extends keyof TCPServerEvents>(event: K, listener: TCPServerEvents[K]): this;
    emit<K extends keyof TCPServerEvents>(event: K, ...args: Parameters<TCPServerEvents[K]>): boolean;
    protected _handle(client: tcp.Socket): Promise<void>;
    protected _response(client: tcp.Socket, message: Packet): void;
}
