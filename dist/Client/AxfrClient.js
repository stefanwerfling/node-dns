import { Buffer } from 'buffer';
import tcp from 'net';
import tls from 'tls';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { AClient } from './AClient.js';
import { ClientOptionsProtocol } from './ClientOptions.js';
export class AxfrClient extends AClient {
    static makeQuery(zoneName) {
        const packet = new Packet();
        packet.header.id = Math.floor(Math.random() * 0x10000);
        packet.header.rd = 0;
        packet.questions.push(new PacketQuestion(zoneName, PacketTypes.AXFR, PacketClass.IN));
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
        return (zoneName) => {
            return new Promise((resolve, reject) => {
                const socket = AxfrClient.connect(option);
                const records = [];
                let soaSeen = 0;
                let soaRecord = null;
                let buffer = Buffer.alloc(0);
                let settled = false;
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
                const tryParse = () => {
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
                                }
                                else if (soaSeen === 2) {
                                    finish(null, {
                                        soa: soaRecord,
                                        records: records,
                                    });
                                    return;
                                }
                            }
                            else {
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
                socket.on('data', (chunk) => {
                    buffer = Buffer.concat([buffer, chunk]);
                    tryParse();
                });
                const send = () => {
                    const query = AxfrClient.makeQuery(zoneName);
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
}
//# sourceMappingURL=AxfrClient.js.map