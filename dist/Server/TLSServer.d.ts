import tcp from 'net';
import tls from 'tls';
import { ServerOptions } from './ServerOptions.js';
import { TCPServer } from './TCPServer.js';
export declare class TLSServer extends TCPServer {
    constructor(options?: ServerOptions | null);
    protected _loadHooks(): void;
    protected _createInternalServer(listener: (socket: tcp.Socket) => void): tls.Server;
}
