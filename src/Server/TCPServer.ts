import {Buffer} from 'buffer';
import dgram from 'dgram';
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
    listening: () => void;
    close: () => void;
};

export type TCPRequestPre = (data: Buffer) => Promise<Buffer>;

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
     * pre request, you can change buffer
     * @protected
     */
    protected _preRequest?: TCPRequestPre;

    /**
     * Constructor
     * @param {ServerOptions|null} options
     */
    public constructor(options: ServerOptions|null = null) {
        this._options = options;

        this._tcpServer = tcp.createServer((socket) => {
            this._handle(socket).catch(err => {
                this._tcpServer?.emit('requestError', err instanceof Error ? err : new Error(String(err)));
            });
        });
    }

    /**
     * Listen
     * @param args
     */
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

    /**
     * on
     * @param event
     * @param listener
     */
    public on<K extends keyof TCPServerEvents>(event: K, listener: TCPServerEvents[K]): this {
        this._tcpServer.on(event, listener);
        return this;
    }

    /**
     * once
     * @param event
     * @param listener
     */
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
            let data = await SocketReader.readStream(client);

            if (this._preRequest) {
                data = await this._preRequest(data);
            }

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

    /**
     * Return the address of the server
     * @return {AddressInfo|string|null}
     */
    public address(): tcp.AddressInfo|string|null {
        return this._tcpServer.address();
    }

    /**
     * Set the pre request, for change buffer
     * @param {TCPRequestPre} preReq
     */
    public setPreRequest(preReq: TCPRequestPre): void {
        this._preRequest = preReq;
    }

}