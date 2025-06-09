import tcp from 'net';
import { SocketReader } from '../Lib/SocketReader.js';
import { Packet } from '../Packet/Packet.js';
export class TCPServer extends tcp.Server {
    _options = null;
    constructor(options = null) {
        super();
        this._options = options;
        super.on('connection', this._handle);
    }
    on(event, listener) {
        super.on(event, listener);
        return this;
    }
    once(event, listener) {
        super.once(event, listener);
        return this;
    }
    emit(event, ...args) {
        return super.emit(event, ...args);
    }
    async _handle(client) {
        try {
            const data = await SocketReader.readStream(client);
            const message = Packet.parse(data);
            super.emit('request', message, this._response.bind(this, client), client);
        }
        catch (e) {
            super.emit('requestError', e);
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