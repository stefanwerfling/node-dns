import dgram from 'dgram';
import { Packet } from '../Packet/Packet.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { EDNS, EdnsECS } from '../Packet/Types/EDNS.js';
import { AClient } from './AClient.js';
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
            return new Promise((resolve, reject) => {
                client.once('message', (message) => {
                    client.close();
                    const response = Packet.parse(message);
                    resolve(response);
                });
                const buffer = query.toBuffer();
                client.send(buffer, port, dns, (err) => {
                    if (err) {
                        reject(err);
                    }
                });
            });
        };
    }
}
//# sourceMappingURL=UDPClient.js.map