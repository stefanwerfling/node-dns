import dgram from 'dgram';
import { Random0x20 } from '../Lib/Random0x20.js';
import { Packet } from '../Packet/Packet.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { EDNS, EdnsECS } from '../Packet/Types/EDNS.js';
import { AClient } from './AClient.js';
import { ClientCookieJar } from './ClientCookieJar.js';
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
        const cookieJar = option.cookies === true
            ? new ClientCookieJar()
            : (option.cookies instanceof ClientCookieJar ? option.cookies : null);
        const sendOnce = async (query) => {
            if (cookieJar !== null) {
                cookieJar.attachTo(query, dns, port);
            }
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
            if (cookieJar !== null) {
                cookieJar.learnFromResponse(response, dns, port);
            }
            return response;
        };
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
            const query = UDPClient.makeQuery(sentName, type, cls, clientIp, recursive);
            let response = await sendOnce(query);
            if (cookieJar !== null && ClientCookieJar.isBadCookie(response)) {
                const retryQuery = UDPClient.makeQuery(sentName, type, cls, clientIp, recursive);
                retryQuery.header.id = query.header.id;
                response = await sendOnce(retryQuery);
            }
            if (option.use0x20 === true && response.questions.length > 0) {
                if (!Random0x20.matches(sentName, response.questions[0].name)) {
                    throw new Error(`0x20 mismatch: sent "${sentName}", got "${response.questions[0].name}" — response may be spoofed`);
                }
            }
            if (tcpFallback && response.header.tc === 1) {
                const tcpResolve = TCPClient.request({
                    dns: dns,
                    port: tcpFallbackPort,
                    use0x20: option.use0x20,
                });
                return tcpResolve(name, type, cls, options);
            }
            return response;
        };
    }
}
//# sourceMappingURL=UDPClient.js.map