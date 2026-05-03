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
import {ClientOptions, ClientOptionsProtocol} from './ClientOptions.js';
import {ClientRequest} from './ClientRequest.js';
import {TcpConnectionPool, TcpConnectionPoolTarget} from './TcpConnectionPool.js';

/**
 * TCPClient
 */
export class TCPClient extends AClient {

    public static makeQuery(name: string, type: PacketTypes|number, cls: PacketClass, clientIp: string|null = null, recursive: boolean = true): Buffer {
        const packet = new Packet();
        packet.header.rd = recursive ? 1 : 0;

        if (clientIp !== null) {
            packet.additionals.push(
                EDNS.createResource([new EdnsECS(clientIp)])
            );
        }

        packet.questions.push(new PacketQuestion(name, type, cls));

        return packet.toBuffer();
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

            const message = TCPClient.makeQuery(sentName, type, cls, clientIp, recursive);
            const [ host ] = option.dns.split(':');

            let data: Buffer;

            if (option.pool !== undefined) {
                const target: TcpConnectionPoolTarget = {
                    protocol: protocol === ClientOptionsProtocol.tls ? 'tls' : 'tcp',
                    host: host,
                    port: port,
                    tlsOptions: option.poolDefaults?.tlsOptions
                };
                data = await option.pool.send(target, message);
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

            if (option.use0x20 === true && response.questions.length > 0) {
                if (!Random0x20.matches(sentName, response.questions[0].name)) {
                    throw new Error(`0x20 mismatch: sent "${sentName}", got "${response.questions[0].name}" — response may be spoofed`);
                }
            }

            return response;
        };
    }

}