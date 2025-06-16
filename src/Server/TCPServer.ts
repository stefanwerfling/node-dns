import tcp from 'net';
import {SocketReader} from '../Lib/SocketReader.js';
import {Packet} from '../Packet/Packet.js';
import {ServerOptions} from './ServerOptions.js';

/**
 * TCP Server Events
 */
export type TCPServerEvents = {
    request: (msgRequest: Packet, send: (request: Packet) => void, client: tcp.Socket) => void;
    requestError: (error: Error) => void;
};

/**
 * TCP Server
 */
export class TCPServer {

    /**
     * Internal tcp server
     * @protected
     */
    protected _tcpServer: tcp.Server;

    /**
     * Options
     * @protected
     */
    protected _options: ServerOptions|null = null;

    /**
     * Constructor
     * @param {ServerOptions|null} options
     */
    public constructor(options: ServerOptions|null = null) {
        this._options = options;
        this._tcpServer = tcp.createServer(this._handle.bind(this));
    }

    public listen(...args: Parameters<tcp.Server['listen']>): this {
        this._tcpServer.listen(...args);
        return this;
    }

    /**
     * Close
     * @param callback
     */
    public close(callback?: (err?: Error) => void): void {
        this._tcpServer.close(callback);
    }

    public on<K extends keyof TCPServerEvents>(event: K, listener: TCPServerEvents[K]): this {
        this._tcpServer.on(event, listener);
        return this;
    }

    public once<K extends keyof TCPServerEvents>(event: K, listener: TCPServerEvents[K]): this {
        this._tcpServer.once(event, listener);
        return this;
    }

    /**
     * Handle client messages
     * @param {tcp.Socket} client
     * @protected
     */
    protected async _handle(client: tcp.Socket): Promise<void> {
        try {
            const data = await SocketReader.readStream(client);
            const message = Packet.parse(data);

            this._tcpServer.emit('request', message, this._response.bind(this, client), client);
        } catch (e) {
            this._tcpServer.emit('requestError', e instanceof Error ? e : new Error(String(e)));
            client.destroy();
        }
    }

    /**
     * Handle client messages response
     * @param {tcp.Socket} client
     * @param {Packet} message
     * @protected
     */
    protected _response(client: tcp.Socket, message: Packet): void {
        const buffer = message.toBuffer();
        const len = Buffer.alloc(2);

        len.writeUInt16BE(buffer.length);

        client.end(Buffer.concat([len, buffer]));
    }

}