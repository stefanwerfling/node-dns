import dgram from 'dgram';
import {Random0x20} from '../Lib/Random0x20.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {EDNS, EdnsECS} from '../Packet/Types/EDNS.js';
import {AClient} from './AClient.js';
import {ClientCookieJar} from './ClientCookieJar.js';
import {ClientOptions} from './ClientOptions.js';
import {ClientRequest} from './ClientRequest.js';
import {TCPClient} from './TCPClient.js';

/**
 * UDPClient
 */
export class UDPClient extends AClient {

    /**
     * Build a query packet
     * @param {string} name
     * @param {PacketTypes|number} type
     * @param {PacketClass} cls
     * @param {string|null} clientIp
     * @param {boolean} recursive
     * @return {Packet}
     */
    public static makeQuery(
        name: string,
        type: PacketTypes|number,
        cls: PacketClass,
        clientIp: string|null = null,
        recursive: boolean = true
    ): Packet {
        const query = new Packet();

        // eslint-disable-next-line no-bitwise
        query.header.id = (Math.random() * 1e4) | 0;
        query.header.rd = recursive ? 1 : 0;

        if (clientIp !== null) {
            query.additionals.push(
                EDNS.createResource([new EdnsECS(clientIp)])
            );
        }

        query.questions.push(new PacketQuestion(name, type, cls));

        return query;
    }

    /**
     * Create a resolver function
     * @param {ClientOptions} option
     * @return {ClientRequest}
     */
    public static request(option: ClientOptions): ClientRequest {
        const dns = option.dns || '8.8.8.8';
        const port = option.port || 53;
        const socketType: 'udp4' | 'udp6' = 'udp4';
        const tcpFallback = option.tcpFallback !== false;
        const tcpFallbackPort = option.tcpFallbackPort === undefined ? port : option.tcpFallbackPort;
        const cookieJar: ClientCookieJar | null = option.cookies === true
            ? new ClientCookieJar()
            : (option.cookies instanceof ClientCookieJar ? option.cookies : null);

        const sendOnce = async(query: Packet): Promise<Packet> => {
            if (cookieJar !== null) {
                cookieJar.attachTo(query, dns, port);
            }

            const client = dgram.createSocket(socketType);

            const response = await new Promise<Packet>((resolve, reject) => {
                client.once('message', (message: Buffer) => {
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

        return async(name, type, cls, options): Promise<Packet> => {
            let clientIp: string|null = null;
            let recursive: boolean = true;

            if (options) {
                if (options.clientIp !== undefined) {
                    clientIp = options.clientIp;
                }

                if (options.recursive !== undefined) {
                    recursive = options.recursive;
                }
            }

            // 0x20 case-randomization (RFC 5452 §9.2) — randomize the QNAME
            // before sending, verify the server echoed back the same case.
            const sentName = option.use0x20 === true ? Random0x20.scramble(name) : name;

            const query = UDPClient.makeQuery(sentName, type, cls, clientIp, recursive);
            let response = await sendOnce(query);

            // RFC 7873 §5.3 — BADCOOKIE means the upstream issued a fresh
            // server cookie alongside the rejection. Retry the same query
            // exactly once; the jar has already learned the new cookie.
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

            // RFC 7766 §8 — if the response is truncated, retry via TCP.
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