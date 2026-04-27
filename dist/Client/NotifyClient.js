import { Buffer } from 'buffer';
import dgram from 'dgram';
import tcp from 'net';
import tls from 'tls';
import { SocketReader } from '../Lib/SocketReader.js';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketOpcode } from '../Packet/PacketOpcode.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { AClient } from './AClient.js';
import { ClientOptionsProtocol } from './ClientOptions.js';
export class NotifyClient extends AClient {
    static makeQuery(zoneName, sourceSoa) {
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
    static request(option) {
        const protocol = option.protocol ?? ClientOptionsProtocol.udp;
        const [host] = option.dns.split(':');
        const port = option.port ?? (protocol === ClientOptionsProtocol.tls ? 853 : 53);
        return (zoneName) => {
            const query = NotifyClient.makeQuery(zoneName, option.sourceSoa);
            const buffer = query.toBuffer();
            if (protocol === ClientOptionsProtocol.udp) {
                return NotifyClient._sendUdp(host, port, buffer);
            }
            return NotifyClient._sendStream(host, port, buffer, protocol === ClientOptionsProtocol.tls);
        };
    }
    static _sendUdp(host, port, query) {
        return new Promise((resolve, reject) => {
            const socket = dgram.createSocket('udp4');
            let settled = false;
            const finish = (err, packet) => {
                if (settled) {
                    return;
                }
                settled = true;
                socket.close();
                if (err) {
                    reject(err);
                }
                else {
                    resolve(packet);
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
    static _sendStream(host, port, query, useTls) {
        return new Promise((resolve, reject) => {
            const socket = useTls
                ? tls.connect({ host: host, port: port, servername: host })
                : tcp.connect({ host: host, port: port });
            const onConnect = () => {
                const len = Buffer.alloc(2);
                len.writeUInt16BE(query.length);
                socket.write(Buffer.concat([len, query]));
            };
            if (useTls) {
                socket.once('secureConnect', onConnect);
            }
            else {
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
//# sourceMappingURL=NotifyClient.js.map