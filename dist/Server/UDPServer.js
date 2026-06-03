import dgram from 'dgram';
import { IpBytes } from '../Lib/IpBytes.js';
import { Packet } from '../Packet/Packet.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { EDNS } from '../Packet/Types/EDNS.js';
import { EdnsCookie } from '../Packet/Types/EdnsCookie.js';
const BADCOOKIE_RCODE = 23;
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
                this._cookies = {
                    secret: options.udp.cookies.secret,
                    mode: options.udp.cookies.mode ?? 'lenient',
                    maxAgeSeconds: options.udp.cookies.maxAgeSeconds ?? 3600,
                    udpPayloadSize: options.udp.cookies.udpPayloadSize ?? 1232
                };
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
                const decision = this._evaluateCookie(message, emitRinfo.address);
                if (decision.action === 'badcookie') {
                    await this._sendCookieReject(rinfo, message, BADCOOKIE_RCODE, decision.clientCookie, decision.freshServerCookie);
                    this._socket.emit('cookieRejected', message, emitRinfo, decision.reason);
                    return;
                }
                if (decision.action === 'refused') {
                    await this._sendCookieReject(rinfo, message, 5, null, null);
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
    _evaluateCookie(message, clientAddress) {
        const incoming = UDPServer._findCookieOption(message);
        if (incoming === null) {
            if (this._cookies.mode === 'strict') {
                return { action: 'refused', reason: 'no-cookie-strict', clientCookie: null, freshServerCookie: null };
            }
            return { action: 'allow', clientCookie: null, freshServerCookie: null };
        }
        let clientIpBytes;
        try {
            clientIpBytes = IpBytes.parse(clientAddress);
        }
        catch {
            return { action: 'refused', reason: 'invalid-cookie', clientCookie: null, freshServerCookie: null };
        }
        const fresh = EdnsCookie.computeServerCookie(incoming.clientCookie, clientIpBytes, this._cookies.secret);
        if (incoming.serverCookie === null) {
            return {
                action: 'badcookie',
                reason: 'no-server-cookie',
                clientCookie: incoming.clientCookie,
                freshServerCookie: fresh
            };
        }
        const valid = EdnsCookie.verifyServerCookie(incoming.serverCookie, incoming.clientCookie, clientIpBytes, this._cookies.secret, this._cookies.maxAgeSeconds > 0 ? { maxAgeSeconds: this._cookies.maxAgeSeconds } : {});
        if (!valid) {
            return {
                action: 'badcookie',
                reason: 'invalid-cookie',
                clientCookie: incoming.clientCookie,
                freshServerCookie: fresh
            };
        }
        return {
            action: 'allow',
            clientCookie: incoming.clientCookie,
            freshServerCookie: fresh
        };
    }
    _sendCookieReject(rinfo, request, rcode, clientCookie, freshServerCookie) {
        const response = new Packet();
        response.header.id = request.header.id;
        response.header.qr = 1;
        response.header.opcode = request.header.opcode;
        response.header.rd = request.header.rd;
        response.questions = request.questions.map((q) => new PacketQuestion(q.name, q.type, q.class));
        if (rcode === BADCOOKIE_RCODE) {
            response.header.rcode = rcode & 0x0F;
            response.additionals.push(this._buildCookieOpt(clientCookie, freshServerCookie, (rcode >> 4) << 24));
        }
        else {
            response.header.rcode = rcode;
            if (clientCookie !== null && freshServerCookie !== null) {
                response.additionals.push(this._buildCookieOpt(clientCookie, freshServerCookie, 0));
            }
        }
        return this._response(rinfo, response);
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
                this._attachOrReplaceCookieOpt(payload, clientCookie, freshServerCookie);
            }
            return this._response(rinfo, payload);
        };
    }
    _buildCookieOpt(clientCookie, serverCookie, extTtl) {
        const rdata = clientCookie !== null
            ? [new EdnsCookie(clientCookie, serverCookie ?? undefined)]
            : [];
        return new PacketResource('', new EDNS(rdata), this._cookies.udpPayloadSize, extTtl);
    }
    _attachOrReplaceCookieOpt(response, clientCookie, serverCookie) {
        const existingIdx = response.additionals.findIndex((r) => r.packetType.type === PacketTypes.EDNS);
        if (existingIdx === -1) {
            response.additionals.push(this._buildCookieOpt(clientCookie, serverCookie, 0));
            return;
        }
        const opt = response.additionals[existingIdx].packetType;
        const otherOptions = opt.rdata.filter((o) => !(o instanceof EdnsCookie));
        opt.rdata = [...otherOptions, new EdnsCookie(clientCookie, serverCookie)];
    }
    static _findCookieOption(message) {
        for (const r of message.additionals) {
            if (r.packetType.type !== PacketTypes.EDNS) {
                continue;
            }
            for (const opt of r.packetType.rdata) {
                if (opt instanceof EdnsCookie) {
                    return opt;
                }
            }
        }
        return null;
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