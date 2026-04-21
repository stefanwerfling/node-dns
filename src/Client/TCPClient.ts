import tcp from 'net';
import tls from 'tls';
import {SocketReader} from '../Lib/SocketReader.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {EDNS, EdnsECS} from '../Packet/Types/EDNS.js';
import {AClient} from './AClient.js';
import {ClientOptions, ClientOptionsProtocol} from './ClientOptions.js';
import {ClientRequest} from './ClientRequest.js';

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

            const message = TCPClient.makeQuery(name, type, cls, clientIp, recursive);
            const [ host ] = option.dns.split(':');
            const client = TCPClient.getClient(protocol, host, port);

            TCPClient.sendQuery(client, message);
            const data = await SocketReader.readStream(client);
            client.end();

            if (!data.length) {
                throw new Error('Empty response');
            }

            return Packet.parse(data);
        };
    }

}