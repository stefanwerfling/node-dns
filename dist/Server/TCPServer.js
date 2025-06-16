import tcp from 'net';
import { SocketReader } from '../Lib/SocketReader.js';
import { Packet } from '../Packet/Packet.js';
export class TCPServer {
    _tcpServer;
    _options = null;
    constructor(options = null) {
        this._options = options;
        this._tcpServer = tcp.createServer(this._handle.bind(this));
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
            const data = await SocketReader.readStream(client);
            const message = Packet.parse(data);
            this._tcpServer.emit('request', message, this._response.bind(this, client), client);
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
}
//# sourceMappingURL=TCPServer.js.map