import dgram from 'dgram';
import { Packet } from '../Packet/Packet.js';
import { CookieGuard } from './CookieGuard.js';
export class UDPServer {
    _socket;
    _preRequest;
    _rrl;
    _cookies;
    constructor(options = null) {
        let type = 'udp4';
        if (options && typeof options.udp === 'object') {
            if (options.udp.type) {
                type = options.udp.type;
            }
            if (options.udp.preRequest) {
                this._preRequest = options.udp.preRequest;
            }
            if (options.udp.rrl) {
                this._rrl = options.udp.rrl;
            }
            if (options.udp.cookies) {
                this._cookies = new CookieGuard(options.udp.cookies);
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
            if (this._rrl) {
                const qtype = message.questions[0]?.type ?? 0;
                const decision = this._rrl.check(emitRinfo.address, qtype);
                if (decision === 'drop') {
                    this._socket.emit('rateLimited', message, emitRinfo, decision);
                    return;
                }
                if (decision === 'truncate') {
                    await this._sendTruncated(rinfo, message);
                    this._socket.emit('rateLimited', message, emitRinfo, decision);
                    return;
                }
            }
            if (this._cookies) {
                const decision = this._cookies.evaluate(message, emitRinfo.address);
                if (decision.action === 'badcookie') {
                    await this._response(rinfo, this._cookies.buildBadCookieResponse(message, decision.clientCookie, decision.freshServerCookie));
                    this._socket.emit('cookieRejected', message, emitRinfo, decision.reason);
                    return;
                }
                if (decision.action === 'refused') {
                    await this._response(rinfo, this._cookies.buildRefusedResponse(message));
                    this._socket.emit('cookieRejected', message, emitRinfo, decision.reason);
                    return;
                }
                const send = decision.freshServerCookie !== null && decision.clientCookie !== null
                    ? this._cookieAwareSend(rinfo, decision.clientCookie, decision.freshServerCookie)
                    : this._response.bind(this, rinfo);
                this._socket.emit('request', message, send, emitRinfo, tdata);
                return;
            }
            this._socket.emit('request', message, this._response.bind(this, rinfo), emitRinfo, tdata);
        }
        catch (e) {
            this._socket.emit('requestError', e instanceof Error ? e : new Error(String(e)));
        }
    }
    _cookieAwareSend(rinfo, clientCookie, freshServerCookie) {
        return (msg) => {
            let payload;
            if (Array.isArray(msg)) {
                payload = msg[0];
            }
            else {
                payload = msg;
            }
            if (payload instanceof Packet) {
                this._cookies.attachOrReplaceCookieOpt(payload, clientCookie, freshServerCookie);
            }
            return this._response(rinfo, payload);
        };
    }
    _sendTruncated(rinfo, request) {
        const trunc = new Packet();
        trunc.header.id = request.header.id;
        trunc.header.qr = 1;
        trunc.header.opcode = request.header.opcode;
        trunc.header.tc = 1;
        trunc.header.rd = request.header.rd;
        trunc.questions = request.questions.slice();
        return this._response(rinfo, trunc);
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