import { Buffer } from 'buffer';
import dgram from 'dgram';
import tcp from 'net';
import tls from 'tls';
import { SocketReader } from '../Lib/SocketReader.js';
import { Packet } from '../Packet/Packet.js';
import { AClient } from './AClient.js';
import { ClientOptionsProtocol } from './ClientOptions.js';
export class UpdateClient extends AClient {
    static request(option) {
        const protocol = option.protocol ?? ClientOptionsProtocol.udp;
        const [host] = option.dns.split(':');
        const port = option.port ?? (protocol === ClientOptionsProtocol.tls ? 853 : 53);
        return (msg) => {
            let buffer;
            if (Buffer.isBuffer(msg)) {
                buffer = msg;
            }
            else {
                buffer = msg.toBuffer();
            }
            if (protocol === ClientOptionsProtocol.udp) {
                return UpdateClient._sendUdp(host, port, buffer);
            }
            return UpdateClient._sendStream(host, port, buffer, protocol === ClientOptionsProtocol.tls);
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
                    reject(new Error('empty UPDATE response'));
                    return;
                }
                resolve(Packet.parse(data));
            }).catch(reject);
        });
    }
}
//# sourceMappingURL=UpdateClient.js.map