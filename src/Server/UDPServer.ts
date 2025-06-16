import dgram from 'dgram';
import { Buffer } from 'buffer';
import {Packet} from '../Packet/Packet.js';
import {ServerOptions} from './ServerOptions.js';

/**
 * UDP Request Listener
 */
export type UDPRequestListener = (msg: Packet, send: (msg: Packet | Buffer) => Promise<Buffer | void>, rinfo: dgram.RemoteInfo) => void;

/**
 * UDP Server
 */
export class UDPServer {

    /**
     * socket
     * @protected
     */
    protected _socket: dgram.Socket;

    /**
     * constructor
     * @param {[ServerOptions]} options
     */
    public constructor(options?: ServerOptions) {
        let type: 'udp4' | 'udp6' = 'udp4';

        if (options && options.udpType) {
            type = options.udpType;
        }

        this._socket = dgram.createSocket(type);

        this._socket.on('message', this._handle.bind(this));
    }

    /**
     * on for request
     * @param {string} event
     * @param {UDPRequestListener} listener
     * @return {UDPServer}
     */
    public on(event: 'request', listener: UDPRequestListener): this;

    /**
     * on request error
     * @param {string} event
     * @param {(err: unknown) => void} listener
     * @return {UDPServer}
     */
    public on(event: 'requestError', listener: (err: unknown) => void): this;

    /**
     * on
     * @param {string} event
     * @param {(...args: any[]) => void} listener
     * @return {UDPServer}
     */
    public on(event: string, listener: (...args: any[]) => void): this {
        this._socket.on(event, listener);
        return this;
    }

    /**
     * once
     * @param {string} event
     * @param {(...args: any[]) => void} listener
     * @return {UDPServer}
     */
    public once(event: string, listener: (...args: any[]) => void): this {
        this._socket.once(event, listener);
        return this;
    }

    /**
     * handle
     * @param {Buffer} data
     * @param {dgram.RemoteInfo} rinfo
     * @protected
     */
    protected _handle(data: Buffer, rinfo: dgram.RemoteInfo): void {
        try {
            const message = Packet.parse(data);
            this._socket.emit('request', message, this._response.bind(this, rinfo), rinfo);
        } catch (e) {
            this._socket.emit('requestError', e instanceof Error ? e : new Error(String(e)));
        }
    }

    /**
     * response
     * @param {dgram.RemoteInfo} rinfo
     * @param {Packet|Buffer} message
     * @return {Buffer}
     * @protected
     */
    protected _response(rinfo: dgram.RemoteInfo, message: Packet|Buffer): Promise<Buffer|void> {
        const tmessage = message instanceof Packet ? message.toBuffer() : message;

        return new Promise((resolve, reject) => {
            this._socket.send(tmessage, rinfo.port, rinfo.address, (err): void => {
                if (err) {
                    return reject(err);
                }

                return resolve(tmessage);
            });
        });
    }

    /**
     * listen
     * @param {number} port
     * @param {[string]} address
     */
    public listen(port: number, address?: string): Promise<void> {
        return new Promise(resolve => {
            this._socket.bind(port, address, resolve);
        });
    }

    /**
     * close
     * @param {[() => void]} callback
     */
    public close(callback?: () => void): void {
        this._socket.close(callback);
    }

}