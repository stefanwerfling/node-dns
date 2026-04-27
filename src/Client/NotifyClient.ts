import {Buffer} from 'buffer';
import dgram from 'dgram';
import tcp from 'net';
import tls from 'tls';
import {SocketReader} from '../Lib/SocketReader.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketOpcode} from '../Packet/PacketOpcode.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {SOA} from '../Packet/Types/SOA.js';
import {AClient} from './AClient.js';
import {ClientOptionsProtocol} from './ClientOptions.js';

/**
 * Options for `NotifyClient.request`.
 */
export type NotifyClientOptions = {
    /**
     * Secondary nameserver to notify (host or `host:port`).
     */
    dns: string;

    /**
     * Override the destination port. Defaults to 53 (UDP/TCP) or 853 (TLS).
     */
    port?: number;

    /**
     * Transport. UDP is the historical default for NOTIFY; TCP/TLS is also
     * permitted (RFC 1996 §3.3) and useful when the SOA record is large.
     */
    protocol?: ClientOptionsProtocol.udp | ClientOptionsProtocol.tcp | ClientOptionsProtocol.tls;

    /**
     * Optional new SOA to include in the answer section (RFC 1996 §3.7
     * recommends but does not require this; some secondaries use it as a
     * "should I bother fetching" hint).
     */
    sourceSoa?: SOA;
};

/**
 * NOTIFY client (RFC 1996).
 *
 * Primary nameservers send NOTIFY messages to their secondaries to signal
 * that a zone has changed; the secondary then issues an SOA query and, if
 * the serial advanced, an AXFR/IXFR. Use this client whenever your zone
 * data changes — it lets secondaries refresh on the order of milliseconds
 * instead of waiting for the SOA `refresh` interval.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc1996
 */
export class NotifyClient extends AClient {

    /**
     * Build a NOTIFY query packet for the given zone. `opcode` is set to
     * NOTIFY, the AA flag is on (RFC 1996 §3.7), and the question section
     * is `(zone, SOA, IN)`. If `sourceSoa` is provided, the SOA record is
     * placed in the answer section.
     */
    public static makeQuery(zoneName: string, sourceSoa?: SOA): Packet {
        const packet = new Packet();
        packet.header.id = Math.floor(Math.random() * 0x10000);
        packet.header.opcode = PacketOpcode.NOTIFY;
        packet.header.aa = 1;
        packet.header.rd = 0;
        packet.questions.push(new PacketQuestion(zoneName, PacketTypes.SOA, PacketClass.IN));

        if (sourceSoa) {
            packet.answers.push(new PacketResource(zoneName, sourceSoa, PacketClass.IN, 0));
        }

        return packet;
    }

    /**
     * Returns a function that, given a zone name, sends one NOTIFY message
     * and resolves with the secondary's response packet (parsed).
     *
     * On UDP the response is read from the same socket; on TCP/TLS the
     * length-prefixed reply is read off the connection. The promise rejects
     * on transport errors or if the response cannot be parsed.
     */
    public static request(option: NotifyClientOptions): (zoneName: string) => Promise<Packet> {
        const protocol = option.protocol ?? ClientOptionsProtocol.udp;
        const [host] = option.dns.split(':');
        const port = option.port ?? (protocol === ClientOptionsProtocol.tls ? 853 : 53);

        return (zoneName: string): Promise<Packet> => {
            const query = NotifyClient.makeQuery(zoneName, option.sourceSoa);
            const buffer = query.toBuffer();

            if (protocol === ClientOptionsProtocol.udp) {
                return NotifyClient._sendUdp(host, port, buffer);
            }

            return NotifyClient._sendStream(host, port, buffer, protocol === ClientOptionsProtocol.tls);
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
                    reject(new Error('empty NOTIFY response'));
                    return;
                }

                resolve(Packet.parse(data));
            }).catch(reject);
        });
    }

}