import {Buffer} from 'buffer';
import tcp from 'net';
import tls from 'tls';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {SOA} from '../Packet/Types/SOA.js';
import {AClient} from './AClient.js';
import {ClientOptionsProtocol} from './ClientOptions.js';

/**
 * Options for `IxfrClient.request`.
 */
export type IxfrClientOptions = {
    dns: string;
    port?: number;
    protocol?: ClientOptionsProtocol.tcp | ClientOptionsProtocol.tls;
};

/**
 * One incremental change set returned by an IXFR transfer.
 */
export type IxfrChangeSet = {
    fromSerial: number;
    toSerial: number;
    deletions: PacketResource[];
    additions: PacketResource[];
};

/**
 * Result of an IXFR transfer. The shape signals which kind of response the
 * server returned per RFC 1995.
 */
export type IxfrResult =
    | {type: 'noChange'; soa: PacketResource;}
    | {type: 'incremental'; currentSoa: PacketResource; diffs: IxfrChangeSet[];}
    | {type: 'fullAxfr'; soa: PacketResource; records: PacketResource[];};

/**
 * IXFR (incremental zone transfer) client per RFC 1995.
 *
 * The client tells the primary which serial it currently has; the primary
 * either:
 *   - confirms "no change" (one SOA in answer);
 *   - returns the diff sequence walking the client's serial up to current;
 *   - falls back to a full AXFR if no diff is available.
 *
 * `IxfrClient.request(options)` returns a function
 * `(zoneName, currentSoa) => Promise<IxfrResult>` — the caller passes the
 * SOA they currently have so the primary can decide what to send.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc1995
 */
export class IxfrClient extends AClient {

    public static makeQuery(zoneName: string, currentSoa: SOA): Buffer {
        const packet = new Packet();
        packet.header.id = Math.floor(Math.random() * 0x10000);
        packet.header.rd = 0;
        packet.questions.push(new PacketQuestion(zoneName, PacketTypes.IXFR, PacketClass.IN));
        // RFC 1995 §3: client puts its current SOA in the AUTHORITY section
        // so the server knows where to start the diff from.
        packet.authorities.push(new PacketResource(zoneName, currentSoa, PacketClass.IN, 0));
        return packet.toBuffer();
    }

    public static connect(option: IxfrClientOptions): tcp.Socket|tls.TLSSocket {
        const protocol = option.protocol ?? ClientOptionsProtocol.tcp;
        const [host] = option.dns.split(':');
        const port = option.port ?? (protocol === ClientOptionsProtocol.tls ? 853 : 53);

        if (protocol === ClientOptionsProtocol.tls) {
            return tls.connect({host: host, port: port, servername: host});
        }

        return tcp.connect({host: host, port: port});
    }

    public static request(option: IxfrClientOptions): (zoneName: string, currentSoa: SOA) => Promise<IxfrResult> {
        return (zoneName: string, currentSoa: SOA): Promise<IxfrResult> => {
            return new Promise<IxfrResult>((resolve, reject) => {
                const socket = IxfrClient.connect(option);
                const answers: PacketResource[] = [];
                let buffer = Buffer.alloc(0);
                let settled = false;
                let firstSoaSeen = false;

                const finish = (err: Error|null, result?: IxfrResult): void => {
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

                const evaluateComplete = (): boolean => {
                    // Determine whether the answer stream is complete.
                    // RFC 1995 forms terminate when the closing SOA matches the
                    // opening SOA serial; the no-change form is a single SOA.
                    if (answers.length === 1 && answers[0].packetType.type === PacketTypes.SOA) {
                        // Could be no-change OR start of a stream; we only know
                        // when more answers (or an EOF) arrive.
                        return false;
                    }

                    if (answers.length >= 2 && answers[0].packetType.type === PacketTypes.SOA) {
                        const opener = (answers[0].packetType as SOA).serial;
                        const last = answers[answers.length - 1];

                        if (last.packetType.type === PacketTypes.SOA &&
                            (last.packetType as SOA).serial === opener &&
                            answers.length > 1) {
                            return true;
                        }
                    }

                    return false;
                };

                const tryParse = (): void => {
                    while (buffer.length >= 2) {
                        const expected = buffer.readUInt16BE(0);

                        if (buffer.length < 2 + expected) {
                            return;
                        }

                        const message = Packet.parse(buffer.subarray(2, 2 + expected));
                        buffer = buffer.subarray(2 + expected);

                        for (const ans of message.answers) {
                            answers.push(ans);

                            if (!firstSoaSeen && ans.packetType.type === PacketTypes.SOA) {
                                firstSoaSeen = true;
                            }
                        }

                        if (evaluateComplete()) {
                            finish(null, IxfrClient._classify(answers));
                            return;
                        }
                    }
                };

                socket.once('error', (err) => finish(err instanceof Error ? err : new Error(String(err))));
                socket.once('close', () => {
                    if (settled) {
                        return;
                    }

                    // No-change form: a single SOA answer with serial == current
                    // and the connection closes after one message.
                    if (answers.length === 1 && answers[0].packetType.type === PacketTypes.SOA) {
                        finish(null, {type: 'noChange', soa: answers[0]});
                        return;
                    }

                    finish(new Error('IXFR connection closed before final SOA was seen'));
                });

                socket.on('data', (chunk: Buffer) => {
                    buffer = Buffer.concat([buffer, chunk]);
                    tryParse();
                });

                const send = (): void => {
                    const query = IxfrClient.makeQuery(zoneName, currentSoa);
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

    /**
     * Classify a complete answer stream into one of the three IXFR shapes.
     * @protected
     */
    protected static _classify(answers: PacketResource[]): IxfrResult {
        // No-change shape is detected before reaching here (single SOA on EOF);
        // by the time _classify runs we have at least an opening SOA, content,
        // and a closing SOA at index `answers.length - 1`.
        const opener = answers[0];
        const closer = answers[answers.length - 1];
        const openerSerial = (opener.packetType as SOA).serial;
        const closerSerial = (closer.packetType as SOA).serial;

        if (openerSerial !== closerSerial) {
            // Should not happen for a well-formed reply, but be defensive.
            return {type: 'fullAxfr', soa: opener, records: answers.slice(1, -1)};
        }

        // Distinguish AXFR-fallback from incremental: AXFR has exactly one
        // opening + one closing SOA and no other SOA in between (any other
        // SOA marks a diff boundary). Incremental responses have an even
        // number of additional SOAs framing each (delete-block, add-block).
        const middle = answers.slice(1, -1);
        const hasInteriorSoa = middle.some((r) => r.packetType.type === PacketTypes.SOA);

        if (!hasInteriorSoa) {
            return {type: 'fullAxfr', soa: opener, records: middle};
        }

        // Incremental: walk pairs of (SOA-from, deletions…, SOA-to, additions…).
        const diffs: IxfrChangeSet[] = [];
        let i = 0;

        while (i < middle.length) {
            if (middle[i].packetType.type !== PacketTypes.SOA) {
                throw new Error(`malformed IXFR response at answer ${i + 1}: expected SOA-from`);
            }

            const fromSerial = (middle[i].packetType as SOA).serial;
            i++;
            const deletions: PacketResource[] = [];

            while (i < middle.length && middle[i].packetType.type !== PacketTypes.SOA) {
                deletions.push(middle[i]);
                i++;
            }

            if (i >= middle.length) {
                throw new Error('malformed IXFR response: missing SOA-to');
            }

            const toSerial = (middle[i].packetType as SOA).serial;
            i++;
            const additions: PacketResource[] = [];

            while (i < middle.length && middle[i].packetType.type !== PacketTypes.SOA) {
                additions.push(middle[i]);
                i++;
            }

            diffs.push({
                fromSerial: fromSerial,
                toSerial: toSerial,
                deletions: deletions,
                additions: additions,
            });
        }

        return {type: 'incremental', currentSoa: opener, diffs: diffs};
    }

}