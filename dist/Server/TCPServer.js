import { Buffer } from 'buffer';
import tcp from 'net';
import { SocketReader } from '../Lib/SocketReader.js';
import { Packet } from '../Packet/Packet.js';
import { CookieGuard } from './CookieGuard.js';
export class TCPServer {
    _tcpServer;
    _options = null;
    _preRequest;
    _preConnection;
    _cookies;
    constructor(options = null) {
        this._options = options;
        this._loadHooks();
        this._tcpServer = this._createInternalServer((socket) => {
            this._handle(socket).catch(err => {
                this._tcpServer?.emit('requestError', err instanceof Error ? err : new Error(String(err)));
            });
        });
    }
    _loadHooks() {
        const opt = this._options?.tcp;
        if (opt && typeof opt === 'object') {
            if (opt.preRequest) {
                this._preRequest = opt.preRequest;
            }
            if (opt.preConnection) {
                this._preConnection = opt.preConnection;
            }
            if (opt.cookies) {
                this._cookies = new CookieGuard(opt.cookies);
            }
        }
    }
    _createInternalServer(listener) {
        return tcp.createServer(listener);
    }
    listen(...args) {
        this._tcpServer.listen(...args);
        return this;
    }
    close(callback) {
        this._tcpServer.close(callback);
    }
    on(event, listener) {
        this._tcpServer.on(event, listener);
        return this;
    }
    once(event, listener) {
        this._tcpServer.once(event, listener);
        return this;
    }
    async _handle(client) {
        try {
            let emitClient = client;
            let initialBuffer;
            if (this._preConnection) {
                const pre = await this._preConnection.process(client);
                if (pre.client) {
                    emitClient = pre.client;
                }
                initialBuffer = pre.initialBuffer;
            }
            let data = await SocketReader.readStream(client, initialBuffer);
            if (this._preRequest) {
                const result = await this._preRequest.process(data, client);
                data = result.data;
                if (result.client) {
                    emitClient = result.client;
                }
            }
            const message = Packet.parse(data);
            if (this._cookies) {
                const clientAddress = emitClient.remoteAddress ?? client.remoteAddress ?? '';
                const decision = this._cookies.evaluate(message, clientAddress);
                if (decision.action === 'badcookie') {
                    this._response(client, this._cookies.buildBadCookieResponse(message, decision.clientCookie, decision.freshServerCookie));
                    this._tcpServer.emit('cookieRejected', message, emitClient, decision.reason);
                    return;
                }
                if (decision.action === 'refused') {
                    this._response(client, this._cookies.buildRefusedResponse(message));
                    this._tcpServer.emit('cookieRejected', message, emitClient, decision.reason);
                    return;
                }
                const send = decision.freshServerCookie !== null && decision.clientCookie !== null
                    ? this._cookieAwareSend(client, decision.clientCookie, decision.freshServerCookie)
                    : this._response.bind(this, client);
                this._tcpServer.emit('request', message, send, emitClient, data);
                return;
            }
            this._tcpServer.emit('request', message, this._response.bind(this, client), emitClient, data);
        }
        catch (e) {
            this._tcpServer.emit('requestError', e instanceof Error ? e : new Error(String(e)));
            client.destroy();
        }
    }
    _cookieAwareSend(client, clientCookie, freshServerCookie) {
        return (msg) => {
            if (msg instanceof Packet) {
                this._cookies.attachOrReplaceCookieOpt(msg, clientCookie, freshServerCookie);
            }
            else if (Array.isArray(msg) && msg.length === 1 && msg[0] instanceof Packet) {
                this._cookies.attachOrReplaceCookieOpt(msg[0], clientCookie, freshServerCookie);
            }
            this._response(client, msg);
        };
    }
    _response(client, message) {
        const messages = Array.isArray(message) ? message : [message];
        if (messages.length === 0) {
            client.end();
            return;
        }
        const chunks = [];
        for (const m of messages) {
            const buffer = Buffer.isBuffer(m) ? m : m.toBuffer();
            const len = Buffer.alloc(2);
            len.writeUInt16BE(buffer.length);
            chunks.push(len, buffer);
        }
        client.end(Buffer.concat(chunks));
    }
    address() {
        return this._tcpServer.address();
    }
}
//# sourceMappingURL=TCPServer.js.map