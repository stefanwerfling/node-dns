import dgram from 'dgram';
import { Packet } from '../Packet/Packet.js';
export class UDPServer {
    _socket;
    _preRequest;
    constructor(options = null) {
        let type = 'udp4';
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
    on(event, listener) {
        this._socket.on(event, listener);
        return this;
    }
    once(event, listener) {
        this._socket.once(event, listener);
        return this;
    }
    async _handle(data, rinfo) {
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
            this._socket.emit('request', message, this._response.bind(this, rinfo), emitRinfo);
        }
        catch (e) {
            this._socket.emit('requestError', e instanceof Error ? e : new Error(String(e)));
        }
    }
    _response(rinfo, message) {
        let payload;
        if (Array.isArray(message)) {
            payload = message[0];
        }
        else {
            payload = message;
        }
        const tmessage = payload instanceof Packet ? payload.toBuffer() : payload;
        return new Promise((resolve, reject) => {
            this._socket.send(tmessage, rinfo.port, rinfo.address, (err) => {
                if (err) {
                    return reject(err);
                }
                return resolve(tmessage);
            });
        });
    }
    listen(port, address) {
        return new Promise(resolve => {
            this._socket.bind(port, address, resolve);
        });
    }
    close(callback) {
        this._socket.close(callback);
    }
    address() {
        return this._socket.address();
    }
}
//# sourceMappingURL=UDPServer.js.map