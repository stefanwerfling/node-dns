import {Buffer} from 'buffer';
import tcp from 'net';
import tls from 'tls';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {AClient} from './AClient.js';
import {ClientOptionsProtocol} from './ClientOptions.js';

/**
 * Options for `AxfrClient.request`.
 */
export type AxfrClientOptions = {
    /**
     * Server address (host or `host:port`). Port from the host string is
     * ignored if `port` is given separately.
     */
    dns: string;

    /**
     * Override the transport port. Defaults to 53 (TCP) or 853 (TLS).
     */
    port?: number;

    /**
     * Choose `tcp` (default) or `tls` for the AXFR connection. UDP is not a
     * legal AXFR transport (RFC 5936 §4.2).
     */
    protocol?: ClientOptionsProtocol.tcp | ClientOptionsProtocol.tls;
};

/**
 * Result of an AXFR transfer.
 */
export type AxfrResult = {
    /**
     * The starting/ending SOA record (RFC 5936 §2.2). Both occurrences in the
     * stream refer to the same zone state, so we expose just one reference.
     */
    soa: PacketResource;

    /**
     * Every zone record returned by the server, in the order received,
     * stripped of the closing SOA marker. The opening SOA is index 0.
     */
    records: PacketResource[];
};

/**
 * AXFR (full zone transfer) client per RFC 5936.
 *
 * Opens a single TCP/TLS connection, sends one AXFR query, and reassembles
 * the multi-message response stream until the second occurrence of the SOA
 * (the "ending SOA") marks completion.
 */
export class AxfrClient extends AClient {

    /**
     * Build a query packet for `QTYPE=AXFR`.
     */
    public static makeQuery(zoneName: string): Buffer {
        const packet = new Packet();
        packet.header.id = Math.floor(Math.random() * 0x10000);
        // RFC 5936 §2.1.2: AXFR queries MUST have RD = 0 (recursion not
        // applicable to zone transfers).
        packet.header.rd = 0;
        packet.questions.push(new PacketQuestion(zoneName, PacketTypes.AXFR, PacketClass.IN));
        return packet.toBuffer();
    }

    /**
     * Open the transport socket. TLS uses port 853 by default.
     */
    public static connect(option: AxfrClientOptions): tcp.Socket|tls.TLSSocket {
        const protocol = option.protocol ?? ClientOptionsProtocol.tcp;
        const [host] = option.dns.split(':');
        const port = option.port ?? (protocol === ClientOptionsProtocol.tls ? 853 : 53);

        if (protocol === ClientOptionsProtocol.tls) {
            return tls.connect({host: host, port: port, servername: host});
        }

        return tcp.connect({host: host, port: port});
    }

    /**
     * Returns a resolver function: call it with a zone name to perform the
     * transfer. The returned promise resolves with `{soa, records}`; the
     * records array starts with the opening SOA and contains every record
     * the server emitted, with the closing SOA stripped.
     */
    public static request(option: AxfrClientOptions): (zoneName: string) => Promise<AxfrResult> {
        return (zoneName: string): Promise<AxfrResult> => {
            return new Promise<AxfrResult>((resolve, reject) => {
                const socket = AxfrClient.connect(option);
                const records: PacketResource[] = [];
                let soaSeen = 0;
                let soaRecord: PacketResource|null = null;
                let buffer = Buffer.alloc(0);
                let settled = false;

                const finish = (err: Error|null, result?: AxfrResult): void => {
                    if (settled) {
                        return;
                    }

                    settled = true;
                    socket.destroy();

                    if (err) {
                        reject(err);
                    } else {
                        resolve(result!);
                    }
                };

                const tryParse = (): void => {
                    while (buffer.length >= 2) {
                        const expected = buffer.readUInt16BE(0);

                        if (buffer.length < 2 + expected) {
                            return;
                        }

                        const messageBuf = buffer.subarray(2, 2 + expected);
                        buffer = buffer.subarray(2 + expected);

                        const message = Packet.parse(messageBuf);

                        for (const ans of message.answers) {
                            if (ans.packetType.type === PacketTypes.SOA) {
                                soaSeen++;

                                if (soaSeen === 1) {
                                    soaRecord = ans;
                                    records.push(ans);
                                } else if (soaSeen === 2) {
                                    // Closing SOA — transfer complete.
                                    finish(null, {
                                        soa: soaRecord!,
                                        records: records,
                                    });
                                    return;
                                }
                            } else {
                                records.push(ans);
                            }
                        }
                    }
                };

                socket.once('error', (err) => finish(err instanceof Error ? err : new Error(String(err))));
                socket.once('close', () => {
                    if (!settled) {
                        finish(new Error('AXFR connection closed before final SOA was seen'));
                    }
                });

                socket.on('data', (chunk: Buffer) => {
                    buffer = Buffer.concat([buffer, chunk]);
                    tryParse();
                });

                const send = (): void => {
                    const query = AxfrClient.makeQuery(zoneName);
                    const len = Buffer.alloc(2);
                    len.writeUInt16BE(query.length);
                    socket.write(Buffer.concat([len, query]));
                };

                if (option.protocol === ClientOptionsProtocol.tls) {
                    socket.once('secureConnect', send);
                } else {
                    socket.once('connect', send);
                }
            });
        };
    }

}