"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TCPClient = void 0;
const tslib_1 = require("tslib");
const net_1 = tslib_1.__importDefault(require("net"));
const tls_1 = tslib_1.__importDefault(require("tls"));
const SocketReader_js_1 = require("../Lib/SocketReader.js");
const Packet_js_1 = require("../Packet/Packet.js");
const PacketQuestion_js_1 = require("../Packet/PacketQuestion.js");
const AClient_js_1 = require("./AClient.js");
const ClientOptions_js_1 = require("./ClientOptions.js");
class TCPClient extends AClient_js_1.AClient {
    static makeQuery(name, type, cls, clientIp = null, recursive = true) {
        const packet = new Packet_js_1.Packet();
        packet.header.rd = recursive ? 1 : 0;
        if (clientIp !== null) {
            packet.additionals.push();
        }
        packet.questions.push(new PacketQuestion_js_1.PacketQuestion(name, type, cls));
        return packet.toBuffer();
    }
    static getClient(protocol, host, port) {
        switch (protocol) {
            case ClientOptions_js_1.ClientOptionsProtocol.tls:
                return tls_1.default.connect({
                    host: host,
                    port: port,
                    servername: host
                });
            case ClientOptions_js_1.ClientOptionsProtocol.tcp:
            default:
                return net_1.default.connect({
                    host: host,
                    port: port
                });
        }
    }
    static sendQuery(client, message) {
        const len = Buffer.alloc(2);
        len.writeUInt16BE(message.length);
        client.write(Buffer.concat([len, message]));
    }
    static request(option) {
        let protocol = ClientOptions_js_1.ClientOptionsProtocol.tcp;
        if (option.protocol !== undefined) {
            if ((option.protocol === ClientOptions_js_1.ClientOptionsProtocol.tcp) || (option.protocol === ClientOptions_js_1.ClientOptionsProtocol.tls)) {
                protocol = option.protocol;
            }
            else {
                throw new Error('Protocol must be tcp or tls');
            }
        }
        let port = protocol === ClientOptions_js_1.ClientOptionsProtocol.tls ? 853 : 53;
        if (option.port !== undefined) {
            port = option.port;
        }
        return async (name, type, cls, options) => {
            let clientIp = null;
            let recursive = true;
            if (options) {
                if (options.clientIp !== undefined) {
                    clientIp = options.clientIp;
                }
                if (options.recursive !== undefined) {
                    recursive = options.recursive;
                }
            }
            const message = TCPClient.makeQuery(name, type, cls, clientIp, recursive);
            const [host] = option.dns.split(':');
            const client = TCPClient.getClient(protocol, host, port);
            TCPClient.sendQuery(client, message);
            const data = await SocketReader_js_1.SocketReader.readStream(client);
            client.end();
            if (!data.length) {
                throw new Error('Empty response');
            }
            return Packet_js_1.Packet.parse(data);
        };
    }
}
exports.TCPClient = TCPClient;
//# sourceMappingURL=TCPClient.js.map