import dgram from 'dgram';
import tcp from 'net';
import { SocketReader } from '../Lib/SocketReader.js';
import { Packet } from '../Packet/Packet.js';
export const defaultUdpTransport = (serverIp, port, query) => {
    return new Promise((resolve, reject) => {
        const family = serverIp.includes(':') ? 'udp6' : 'udp4';
        const socket = dgram.createSocket(family);
        let settled = false;
        const finish = (err, packet) => {
            if (settled) {
                return;
            }
            settled = true;
            try {
                socket.close();
            }
            catch {
            }
            if (err) {
                reject(err);
            }
            else {
                resolve(packet);
            }
        };
        socket.once('message', (msg) => {
            try {
                finish(null, Packet.parse(msg));
            }
            catch (err) {
                finish(err instanceof Error ? err : new Error(String(err)));
            }
        });
        socket.once('error', (err) => finish(err));
        socket.send(query.toBuffer(), port, serverIp, (err) => {
            if (err) {
                finish(err);
            }
        });
    });
};
export const defaultTcpTransport = (serverIp, port, query) => {
    return new Promise((resolve, reject) => {
        const socket = tcp.createConnection({ host: serverIp, port: port });
        let settled = false;
        const finish = (err, packet) => {
            if (settled) {
                return;
            }
            settled = true;
            try {
                socket.destroy();
            }
            catch {
            }
            if (err) {
                reject(err);
            }
            else {
                resolve(packet);
            }
        };
        socket.once('connect', () => {
            const message = query.toBuffer();
            const len = Buffer.alloc(2);
            len.writeUInt16BE(message.length);
            socket.write(Buffer.concat([len, message]));
        });
        SocketReader.readStream(socket).then((data) => {
            try {
                finish(null, Packet.parse(data));
            }
            catch (err) {
                finish(err instanceof Error ? err : new Error(String(err)));
            }
        }, (err) => finish(err));
    });
};
//# sourceMappingURL=Transports.js.map