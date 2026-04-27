import { readFileSync } from 'fs';
import http from 'http';
import path from 'path';
import tls from 'tls';
import { fileURLToPath } from 'url';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
export const response = Buffer.from([
    0x29, 0x64, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
    0x01, 0x7a, 0x02, 0x63, 0x6e, 0x00, 0x00, 0x01,
    0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x90, 0x00, 0x04, 0x36, 0xde,
    0x3c, 0xfc
]);
export const get = (url, options) => {
    return new Promise((resolve, reject) => {
        try {
            const req = http.get(url, options || {}, (res) => {
                const result = [];
                res.on('data', (data) => result.push(data));
                res.once('error', reject);
                res.once('end', () => resolve({
                    body: Buffer.concat(result),
                    headers: res.headers,
                }));
            });
            req.on('error', reject);
        }
        catch (err) {
            reject(err);
        }
    });
};
const tlsExampleDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../example/server');
export const tlsCert = readFileSync(path.join(tlsExampleDir, 'server.crt'));
export const tlsKey = readFileSync(path.join(tlsExampleDir, 'secret.key'));
export const dotQuery = (port, name) => {
    return new Promise((resolve, reject) => {
        const socket = tls.connect({
            host: '127.0.0.1',
            port: port,
            rejectUnauthorized: false
        });
        socket.once('error', reject);
        socket.once('secureConnect', () => {
            const request = new Packet();
            request.header.id = 0xBEEF;
            request.header.rd = 1;
            request.questions.push(new PacketQuestion(name, PacketTypes.A, PacketClass.IN));
            const buf = request.toBuffer();
            const len = Buffer.alloc(2);
            len.writeUInt16BE(buf.length);
            socket.write(Buffer.concat([len, buf]));
        });
        const chunks = [];
        socket.on('data', (c) => chunks.push(c));
        socket.on('end', () => {
            const all = Buffer.concat(chunks);
            if (all.length < 2) {
                reject(new Error('truncated DoT response'));
                return;
            }
            const expected = all.readUInt16BE(0);
            if (all.length < 2 + expected) {
                reject(new Error('short DoT response'));
                return;
            }
            resolve(Packet.parse(all.subarray(2, 2 + expected)));
        });
    });
};
//# sourceMappingURL=helpers.js.map