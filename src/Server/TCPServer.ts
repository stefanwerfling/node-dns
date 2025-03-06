import tcp from 'net';
import {SocketReader} from '../Lib/SocketReader.js';
import {Packet} from '../Packet/Packet.js';
import {ServerOptions} from './ServerOptions.js';

/**
 * TCP Server Events
 */
export type TCPServerEvents = {
    request: (msgRequest: Packet, send: (message: Packet) => void, client: tcp.Socket) => void;
    requestError: (error: Error) => void;
};

/**
 * TCP Server
 */
export class TCPServer extends tcp.Server {

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
        super();

        this._options = options;

        super.on('connection', this._handle.bind(this));
    }

    /**
     * on
     * @param {string} event
     * @param {TCPServerEvents} listener
     */
    public on<K extends keyof TCPServerEvents>(event: K, listener: TCPServerEvents[K]): this {
        super.on(event, listener);
        return this;
    }

    /**
     * once
     * @param {string} event
     * @param {TCPServerEvents} listener
     */
    public once<K extends keyof TCPServerEvents>(event: K, listener: TCPServerEvents[K]): this {
        super.once(event, listener);
        return this;
    }

    /**
     * emit
     * @param {string} event
     * @param {Parameters} args
     */
    public emit<K extends keyof TCPServerEvents>(event: K, ...args: Parameters<TCPServerEvents[K]>): boolean {
        return super.emit(event, ...args);
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

            super.emit('request', message, this._response.bind(this, client), client);
        } catch (e) {
            super.emit('requestError', e);
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