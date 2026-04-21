import dgram from 'dgram';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {EDNS, EdnsECS} from '../Packet/Types/EDNS.js';
import {AClient} from './AClient.js';
import {ClientOptions} from './ClientOptions.js';
import {ClientRequest} from './ClientRequest.js';

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

            const query = UDPClient.makeQuery(name, type, cls, clientIp, recursive);
            const client = dgram.createSocket(socketType);

            return new Promise<Packet>((resolve, reject) => {
                client.once('message', (message: Buffer) => {
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