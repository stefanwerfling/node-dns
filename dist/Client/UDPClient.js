import dgram from 'dgram';
import { Packet } from '../Packet/Packet.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { EDNS, EdnsECS } from '../Packet/Types/EDNS.js';
import { AClient } from './AClient.js';
import { TCPClient } from './TCPClient.js';
export class UDPClient extends AClient {
    static makeQuery(name, type, cls, clientIp = null, recursive = true) {
        const query = new Packet();
        query.header.id = (Math.random() * 1e4) | 0;
        query.header.rd = recursive ? 1 : 0;
        if (clientIp !== null) {
            query.additionals.push(EDNS.createResource([new EdnsECS(clientIp)]));
        }
        query.questions.push(new PacketQuestion(name, type, cls));
        return query;
    }
    static request(option) {
        const dns = option.dns || '8.8.8.8';
        const port = option.port || 53;
        const socketType = 'udp4';
        const tcpFallback = option.tcpFallback !== false;
        const tcpFallbackPort = option.tcpFallbackPort === undefined ? port : option.tcpFallbackPort;
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
            const query = UDPClient.makeQuery(name, type, cls, clientIp, recursive);
            const client = dgram.createSocket(socketType);
            const response = await new Promise((resolve, reject) => {
                client.once('message', (message) => {
                    client.close();
                    resolve(Packet.parse(message));
                });
                const buffer = query.toBuffer();
                client.send(buffer, port, dns, (err) => {
                    if (err) {
                        client.close();
                        reject(err);
                    }
                });
            });
            if (tcpFallback && response.header.tc === 1) {
                const tcpResolve = TCPClient.request({
                    dns: dns,
                    port: tcpFallbackPort
                });
                return tcpResolve(name, type, cls, options);
            }
            return response;
        };
    }
}
//# sourceMappingURL=UDPClient.js.map