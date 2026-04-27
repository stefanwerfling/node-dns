import dgram from 'dgram';
import {Buffer} from 'buffer';
import {AddressInfo} from 'net';
import {Packet} from '../Packet/Packet.js';
import {ServerOptions} from './ServerOptions.js';
import {ServerPreRequest} from './ServerPreRequest.js';

/**
 * Reply payload accepted by the UDP `send` callback. UDP cannot stream
 * multiple datagrams as one logical reply, so when an array is passed only
 * the first element is sent and the rest are silently dropped (AXFR-style
 * multi-message responses are TCP-only by design — RFC 5936 §4.2).
 */
export type UDPSendable = Packet | Packet[] | Buffer;

/**
 * UDP Request Listener
 */
export type UDPRequestListener = (msg: Packet, send: (msg: UDPSendable) => Promise<Buffer | void>, rinfo: dgram.RemoteInfo) => void;

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
     * pre request processor, can modify the raw buffer and override the client rinfo
     * @protected
     */
    protected _preRequest?: ServerPreRequest<dgram.RemoteInfo>;

    /**
     * constructor
     * @param {ServerOptions|null} options
     */
    public constructor(options: ServerOptions|null = null) {
        let type: 'udp4' | 'udp6' = 'udp4';

        if (options && typeof options.udp === 'object') {
            if (options.udp.type) {
                type = options.udp.type;
            }

            if (options.udp.preRequest) {
                this._preRequest = options.udp.preRequest;
            }
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
            let emitRinfo = rinfo;

            if (this._preRequest) {
                const result = await this._preRequest.process(tdata, rinfo);
                tdata = result.data;

                if (result.client) {
                    emitRinfo = result.client;
                }
            }

            const message = Packet.parse(tdata);

            // Response always goes back to the transport peer (e.g. the proxy),
            // while the emitted rinfo reflects the (optionally overridden) client.
            this._socket.emit('request', message, this._response.bind(this, rinfo), emitRinfo);
        } catch (e) {
            this._socket.emit('requestError', e instanceof Error ? e : new Error(String(e)));
        }
    }

    /**
     * response
     * @param {dgram.RemoteInfo} rinfo
     * @param {UDPSendable} message single packet, packet array (only first
     *        used) or pre-encoded buffer
     * @return {Buffer}
     * @protected
     */
    protected _response(rinfo: dgram.RemoteInfo, message: UDPSendable): Promise<Buffer|void> {
        let payload: Packet|Buffer;

        if (Array.isArray(message)) {
            // AXFR-style multi-message responses don't fit into a UDP datagram;
            // honour the first packet and drop the rest.
            payload = message[0];
        } else {
            payload = message;
        }

        const tmessage = payload instanceof Packet ? payload.toBuffer() : payload;

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
     * Return the address of the server
     * @return {AddressInfo}
     */
    public address(): AddressInfo {
        return this._socket.address() as AddressInfo;
    }

}