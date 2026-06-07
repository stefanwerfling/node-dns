import tcp from 'net';
import tls from 'tls';
import {Random0x20} from '../Lib/Random0x20.js';
import {SocketReader} from '../Lib/SocketReader.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {EDNS, EdnsECS} from '../Packet/Types/EDNS.js';
import {AClient} from './AClient.js';
import {ClientCookieJar} from './ClientCookieJar.js';
import {ClientOptions, ClientOptionsProtocol} from './ClientOptions.js';
import {ClientRequest} from './ClientRequest.js';
import {TcpConnectionPool, TcpConnectionPoolTarget} from './TcpConnectionPool.js';

/**
 * TCPClient
 */
export class TCPClient extends AClient {

    public static makeQuery(name: string, type: PacketTypes|number, cls: PacketClass, clientIp: string|null = null, recursive: boolean = true): Buffer {
        return TCPClient.makeQueryPacket(name, type, cls, clientIp, recursive).toBuffer();
    }

    /**
     * Build a query as a `Packet` rather than a wire `Buffer`. Used by
     * the cookie-aware request path so the EDNS cookie option can be
     * attached before serialization.
     *
     * @param {string} name
     * @param {PacketTypes|number} type
     * @param {PacketClass} cls
     * @param {string|null} clientIp
     * @param {boolean} recursive
     * @return {Packet}
     */
    public static makeQueryPacket(name: string, type: PacketTypes|number, cls: PacketClass, clientIp: string|null = null, recursive: boolean = true): Packet {
        const packet = new Packet();
        packet.header.rd = recursive ? 1 : 0;

        if (clientIp !== null) {
            packet.additionals.push(
                EDNS.createResource([new EdnsECS(clientIp)])
            );
        }

        packet.questions.push(new PacketQuestion(name, type, cls));

        return packet;
    }

    /**
     * Return a client
     * @param {ClientOptionsProtocol} protocol
     * @param {string} host
     * @param {number} port
     * @return {tcp.Socket|tls.TLSSocket}
     */
    public static getClient(protocol: ClientOptionsProtocol, host: string, port: number): tcp.Socket|tls.TLSSocket {
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

    public static sendQuery(client: tcp.Socket|tls.TLSSocket, message: Buffer): void {
        const len = Buffer.alloc(2);
        len.writeUInt16BE(message.length);
        client.write(Buffer.concat([len, message]));
    }

    /**
     * request
     * @param {ClientOptions} option
     * @return {ClientRequest}
     */
    public static request(option: ClientOptions): ClientRequest {
        let protocol = ClientOptionsProtocol.tcp;

        if (option.protocol !== undefined) {
            if ((option.protocol === ClientOptionsProtocol.tcp) || (option.protocol === ClientOptionsProtocol.tls)) {
                protocol = option.protocol;
            } else {
                throw new Error('Protocol must be tcp or tls');
            }
        }

        let port = protocol === ClientOptionsProtocol.tls ? 853 : 53;

        if (option.port !== undefined) {
            port = option.port;
        }

        const cookieJar: ClientCookieJar | null = option.cookies === true
            ? new ClientCookieJar()
            : (option.cookies instanceof ClientCookieJar ? option.cookies : null);

        const [host] = option.dns.split(':');
        const poolTarget: TcpConnectionPoolTarget = {
            protocol: protocol === ClientOptionsProtocol.tls ? 'tls' : 'tcp',
            host: host,
            port: port,
            tlsOptions: option.poolDefaults?.tlsOptions
        };

        const sendOnce = async(query: Packet): Promise<Packet> => {
            if (cookieJar !== null) {
                cookieJar.attachTo(query, host, port);
            }

            const message = query.toBuffer();

            let data: Buffer;

            if (option.pool !== undefined) {
                data = await option.pool.send(poolTarget, message);
            } else {
                const client = TCPClient.getClient(protocol, host, port);
                TCPClient.sendQuery(client, message);
                data = await SocketReader.readStream(client);
                client.end();
            }

            if (!data.length) {
                throw new Error('Empty response');
            }

            const response = Packet.parse(data);

            if (cookieJar !== null) {
                cookieJar.learnFromResponse(response, host, port);
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

            const sentName = option.use0x20 === true ? Random0x20.scramble(name) : name;

            const query = TCPClient.makeQueryPacket(sentName, type, cls, clientIp, recursive);
            let response = await sendOnce(query);

            // RFC 7873 §5.3 — BADCOOKIE means the upstream issued a fresh
            // server cookie alongside the rejection. Retry once; the jar
            // has already learned the new cookie.
            if (cookieJar !== null && ClientCookieJar.isBadCookie(response)) {
                const retryQuery = TCPClient.makeQueryPacket(sentName, type, cls, clientIp, recursive);
                response = await sendOnce(retryQuery);
            }

            if (option.use0x20 === true && response.questions.length > 0) {
                if (!Random0x20.matches(sentName, response.questions[0].name)) {
                    throw new Error(`0x20 mismatch: sent "${sentName}", got "${response.questions[0].name}" — response may be spoofed`);
                }
            }

            return response;
        };
    }

}