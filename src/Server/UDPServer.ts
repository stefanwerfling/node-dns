import dgram from 'dgram';
import { Buffer } from 'buffer';
import {Packet} from '../Packet/Packet.js';
import {ServerOptions} from './ServerOptions.js';

/**
 * UDP Request Listener
 */
export type UDPRequestListener = (msg: Packet, send: (msg: Packet | Buffer) => Promise<Buffer | void>, rinfo: dgram.RemoteInfo) => void;

/**
 * UDP Request Pre
 */
export type UDPRequestPre = (data: Buffer, rinfo: dgram.RemoteInfo) => Promise<Buffer>;

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
     * pre request, you can change buffer
     * @protected
     */
    protected _preRequest?: UDPRequestPre;

    /**
     * constructor
     * @param {ServerOptions|null} options
     */
    public constructor(options: ServerOptions|null = null) {
        let type: 'udp4' | 'udp6' = 'udp4';

        if (options && options.udp && options.udp.type) {
            type = options.udp.type;
        }

        this._socket = dgram.createSocket(type);

        this._socket.on('message', (data, rinfo) => {
            this._handle(data, rinfo).catch(e => {
                this._socket.emit('requestError', e instanceof Error ? e : new Error(String(e)));
            });
        });
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
    protected async _handle(data: Buffer, rinfo: dgram.RemoteInfo): Promise<void> {
        try {
            let tdata = data;

            if (this._preRequest) {
                tdata = await this._preRequest(tdata, rinfo);
            }

            const message = Packet.parse(tdata);

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

    /**
     * Set the pre request, for change buffer
     * @param {UDPRequestPre} preReq
     */
    public setPreRequest(preReq: UDPRequestPre): void {
        this._preRequest = preReq;
    }

}