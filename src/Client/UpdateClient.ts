import {Buffer} from 'buffer';
import dgram from 'dgram';
import tcp from 'net';
import tls from 'tls';
import {SocketReader} from '../Lib/SocketReader.js';
import {Packet} from '../Packet/Packet.js';
import {UpdateBuilder} from '../Packet/Update.js';
import {AClient} from './AClient.js';
import {ClientOptionsProtocol} from './ClientOptions.js';

/**
 * Options for `UpdateClient.request`.
 */
export type UpdateClientOptions = {
    dns: string;
    port?: number;
    protocol?: ClientOptionsProtocol.udp | ClientOptionsProtocol.tcp | ClientOptionsProtocol.tls;
};

/**
 * DNS UPDATE client (RFC 2136). Sends a single UPDATE message over UDP
 * (default), TCP, or TLS and resolves with the parsed response packet —
 * the response carries the RCODE the server returned (NOERROR, NXRRSET,
 * YXRRSET, NOTAUTH, REFUSED, …).
 *
 * `request(options)` returns a function that accepts either an
 * `UpdateBuilder` (the common path) or a fully-formed `Packet` (when you
 * built the message manually, e.g. after TSIG signing).
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc2136
 */
export class UpdateClient extends AClient {

    public static request(option: UpdateClientOptions): (msg: UpdateBuilder|Packet) => Promise<Packet> {
        const protocol = option.protocol ?? ClientOptionsProtocol.udp;
        const [host] = option.dns.split(':');
        const port = option.port ?? (protocol === ClientOptionsProtocol.tls ? 853 : 53);

        return (msg: UpdateBuilder|Packet): Promise<Packet> => {
            const buffer = msg instanceof UpdateBuilder ? msg.toBuffer() : msg.toBuffer();

            if (protocol === ClientOptionsProtocol.udp) {
                return UpdateClient._sendUdp(host, port, buffer);
            }

            return UpdateClient._sendStream(host, port, buffer, protocol === ClientOptionsProtocol.tls);
        };
    }

    protected static _sendUdp(host: string, port: number, query: Buffer): Promise<Packet> {
        return new Promise((resolve, reject) => {
            const socket = dgram.createSocket('udp4');
            let settled = false;

            const finish = (err: Error|null, packet?: Packet): void => {
                if (settled) {
                    return;
                }

                settled = true;
                socket.close();

                if (err) {
                    reject(err);
                } else {
                    resolve(packet!);
                }
            };

            socket.once('message', (msg) => finish(null, Packet.parse(msg)));
            socket.once('error', (err) => finish(err));
            socket.send(query, port, host, (err) => {
                if (err) {
                    finish(err);
                }
            });
        });
    }

    protected static _sendStream(host: string, port: number, query: Buffer, useTls: boolean): Promise<Packet> {
        return new Promise((resolve, reject) => {
            const socket: tcp.Socket|tls.TLSSocket = useTls
                ? tls.connect({host: host, port: port, servername: host})
                : tcp.connect({host: host, port: port});

            const onConnect = (): void => {
                const len = Buffer.alloc(2);
                len.writeUInt16BE(query.length);
                socket.write(Buffer.concat([len, query]));
            };

            if (useTls) {
                socket.once('secureConnect', onConnect);
            } else {
                socket.once('connect', onConnect);
            }

            socket.once('error', reject);

            SocketReader.readStream(socket).then((data) => {
                socket.end();

                if (!data.length) {
                    reject(new Error('empty UPDATE response'));
                    return;
                }

                resolve(Packet.parse(data));
            }).catch(reject);
        });
    }

}