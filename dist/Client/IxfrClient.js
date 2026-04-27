import { Buffer } from 'buffer';
import tcp from 'net';
import tls from 'tls';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { AClient } from './AClient.js';
import { ClientOptionsProtocol } from './ClientOptions.js';
export class IxfrClient extends AClient {
    static makeQuery(zoneName, currentSoa) {
        const packet = new Packet();
        packet.header.id = Math.floor(Math.random() * 0x10000);
        packet.header.rd = 0;
        packet.questions.push(new PacketQuestion(zoneName, PacketTypes.IXFR, PacketClass.IN));
        packet.authorities.push(new PacketResource(zoneName, currentSoa, PacketClass.IN, 0));
        return packet.toBuffer();
    }
    static connect(option) {
        const protocol = option.protocol ?? ClientOptionsProtocol.tcp;
        const [host] = option.dns.split(':');
        const port = option.port ?? (protocol === ClientOptionsProtocol.tls ? 853 : 53);
        if (protocol === ClientOptionsProtocol.tls) {
            return tls.connect({ host: host, port: port, servername: host });
        }
        return tcp.connect({ host: host, port: port });
    }
    static request(option) {
        return (zoneName, currentSoa) => {
            return new Promise((resolve, reject) => {
                const socket = IxfrClient.connect(option);
                const answers = [];
                let buffer = Buffer.alloc(0);
                let settled = false;
                let firstSoaSeen = false;
                const finish = (err, result) => {
                    if (settled) {
                        return;
                    }
                    settled = true;
                    socket.destroy();
                    if (err) {
                        reject(err);
                    }
                    else {
                        resolve(result);
                    }
                };
                const evaluateComplete = () => {
                    if (answers.length === 1 && answers[0].packetType.type === PacketTypes.SOA) {
                        return false;
                    }
                    if (answers.length >= 2 && answers[0].packetType.type === PacketTypes.SOA) {
                        const opener = answers[0].packetType.serial;
                        const last = answers[answers.length - 1];
                        if (last.packetType.type === PacketTypes.SOA &&
                            last.packetType.serial === opener &&
                            answers.length > 1) {
                            return true;
                        }
                    }
                    return false;
                };
                const tryParse = () => {
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
                    if (answers.length === 1 && answers[0].packetType.type === PacketTypes.SOA) {
                        finish(null, { type: 'noChange', soa: answers[0] });
                        return;
                    }
                    finish(new Error('IXFR connection closed before final SOA was seen'));
                });
                socket.on('data', (chunk) => {
                    buffer = Buffer.concat([buffer, chunk]);
                    tryParse();
                });
                const send = () => {
                    const query = IxfrClient.makeQuery(zoneName, currentSoa);
                    const len = Buffer.alloc(2);
                    len.writeUInt16BE(query.length);
                    socket.write(Buffer.concat([len, query]));
                };
                if (option.protocol === ClientOptionsProtocol.tls) {
                    socket.once('secureConnect', send);
                }
                else {
                    socket.once('connect', send);
                }
            });
        };
    }
    static _classify(answers) {
        const opener = answers[0];
        const closer = answers[answers.length - 1];
        const openerSerial = opener.packetType.serial;
        const closerSerial = closer.packetType.serial;
        if (openerSerial !== closerSerial) {
            return { type: 'fullAxfr', soa: opener, records: answers.slice(1, -1) };
        }
        const middle = answers.slice(1, -1);
        const hasInteriorSoa = middle.some((r) => r.packetType.type === PacketTypes.SOA);
        if (!hasInteriorSoa) {
            return { type: 'fullAxfr', soa: opener, records: middle };
        }
        const diffs = [];
        let i = 0;
        while (i < middle.length) {
            if (middle[i].packetType.type !== PacketTypes.SOA) {
                throw new Error(`malformed IXFR response at answer ${i + 1}: expected SOA-from`);
            }
            const fromSerial = middle[i].packetType.serial;
            i++;
            const deletions = [];
            while (i < middle.length && middle[i].packetType.type !== PacketTypes.SOA) {
                deletions.push(middle[i]);
                i++;
            }
            if (i >= middle.length) {
                throw new Error('malformed IXFR response: missing SOA-to');
            }
            const toSerial = middle[i].packetType.serial;
            i++;
            const additions = [];
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
        return { type: 'incremental', currentSoa: opener, diffs: diffs };
    }
}
//# sourceMappingURL=IxfrClient.js.map