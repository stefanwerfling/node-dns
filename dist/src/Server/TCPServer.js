"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TCPServer = void 0;
const tslib_1 = require("tslib");
const net_1 = tslib_1.__importDefault(require("net"));
const SocketReader_js_1 = require("../Lib/SocketReader.js");
const Packet_js_1 = require("../Packet/Packet.js");
class TCPServer extends net_1.default.Server {
    _options = null;
    constructor(options = null) {
        super();
        this._options = options;
        super.on('connection', this._handle.bind(this));
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
            const data = await SocketReader_js_1.SocketReader.readStream(client);
            const message = Packet_js_1.Packet.parse(data);
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
exports.TCPServer = TCPServer;
//# sourceMappingURL=TCPServer.js.map