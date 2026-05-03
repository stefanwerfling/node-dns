import tcp from 'net';
import tls from 'tls';
import { Random0x20 } from '../Lib/Random0x20.js';
import { SocketReader } from '../Lib/SocketReader.js';
import { Packet } from '../Packet/Packet.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { EDNS, EdnsECS } from '../Packet/Types/EDNS.js';
import { AClient } from './AClient.js';
import { ClientOptionsProtocol } from './ClientOptions.js';
export class TCPClient extends AClient {
    static makeQuery(name, type, cls, clientIp = null, recursive = true) {
        const packet = new Packet();
        packet.header.rd = recursive ? 1 : 0;
        if (clientIp !== null) {
            packet.additionals.push(EDNS.createResource([new EdnsECS(clientIp)]));
        }
        packet.questions.push(new PacketQuestion(name, type, cls));
        return packet.toBuffer();
    }
    static getClient(protocol, host, port) {
        switch (protocol) {
            case ClientOptionsProtocol.tls:
                return tls.connect({
                    host: host,
                    port: port,
                    servername: host
                });
            case ClientOptionsProtocol.tcp:
            default:
                return tcp.connect({
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
        let protocol = ClientOptionsProtocol.tcp;
        if (option.protocol !== undefined) {
            if ((option.protocol === ClientOptionsProtocol.tcp) || (option.protocol === ClientOptionsProtocol.tls)) {
                protocol = option.protocol;
            }
            else {
                throw new Error('Protocol must be tcp or tls');
            }
        }
        let port = protocol === ClientOptionsProtocol.tls ? 853 : 53;
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
            const sentName = option.use0x20 === true ? Random0x20.scramble(name) : name;
            const message = TCPClient.makeQuery(sentName, type, cls, clientIp, recursive);
            const [host] = option.dns.split(':');
            let data;
            if (option.pool !== undefined) {
                const target = {
                    protocol: protocol === ClientOptionsProtocol.tls ? 'tls' : 'tcp',
                    host: host,
                    port: port,
                    tlsOptions: option.poolDefaults?.tlsOptions
                };
                data = await option.pool.send(target, message);
            }
            else {
                const client = TCPClient.getClient(protocol, host, port);
                TCPClient.sendQuery(client, message);
                data = await SocketReader.readStream(client);
                client.end();
            }
            if (!data.length) {
                throw new Error('Empty response');
            }
            const response = Packet.parse(data);
            if (option.use0x20 === true && response.questions.length > 0) {
                if (!Random0x20.matches(sentName, response.questions[0].name)) {
                    throw new Error(`0x20 mismatch: sent "${sentName}", got "${response.questions[0].name}" — response may be spoofed`);
                }
            }
            return response;
        };
    }
}
//# sourceMappingURL=TCPClient.js.map