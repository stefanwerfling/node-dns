import { Buffer } from 'buffer';
import tcp from 'net';
import { SocketReader } from '../Lib/SocketReader.js';
import { Packet } from '../Packet/Packet.js';
export class TCPServer {
    _tcpServer;
    _options = null;
    _preRequest;
    _preConnection;
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
            this._tcpServer.emit('request', message, this._response.bind(this, client), emitClient);
        }
        catch (e) {
            this._tcpServer.emit('requestError', e instanceof Error ? e : new Error(String(e)));
            client.destroy();
        }
    }
    _response(client, message) {
        const buffer = message.toBuffer();
        const len = Buffer.alloc(2);
        len.writeUInt16BE(buffer.length);
        client.end(Buffer.concat([len, buffer]));
    }
    address() {
        return this._tcpServer.address();
    }
}
//# sourceMappingURL=TCPServer.js.map