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
        if (options && typeof options.tcp === 'object') {
            if (options.tcp.preRequest) {
                this._preRequest = options.tcp.preRequest;
            }
            if (options.tcp.preConnection) {
                this._preConnection = options.tcp.preConnection;
            }
        }
        this._tcpServer = tcp.createServer((socket) => {
            this._handle(socket).catch(err => {
                this._tcpServer?.emit('requestError', err instanceof Error ? err : new Error(String(err)));
            });
        });
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