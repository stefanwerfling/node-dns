import dgram from 'dgram';
import { Packet } from '../Packet/Packet.js';
export class UDPServer {
    _socket;
    constructor(options) {
        let type = 'udp4';
        if (options && options.udpType) {
            type = options.udpType;
        }
        this._socket = dgram.createSocket(type);
        this._socket.on('message', this._handle.bind(this));
    }
    on(event, listener) {
        this._socket.on(event, listener);
        return this;
    }
    once(event, listener) {
        this._socket.once(event, listener);
        return this;
    }
    _handle(data, rinfo) {
        try {
            const message = Packet.parse(data);
            this._socket.emit('request', message, this._response.bind(this, rinfo), rinfo);
        }
        catch (e) {
            this._socket.emit('requestError', e instanceof Error ? e : new Error(String(e)));
        }
    }
    _response(rinfo, message) {
        const tmessage = message instanceof Packet ? message.toBuffer() : message;
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
}
//# sourceMappingURL=UDPServer.js.map