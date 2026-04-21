import http from 'http';
import https from 'https';
import http2 from 'http2';
import { Packet } from '../Packet/Packet.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { EDNS, EdnsECS } from '../Packet/Types/EDNS.js';
import { AClient } from './AClient.js';
export class DohClient extends AClient {
    static buildQuery(name, type, cls, clientIp = null, recursive = true) {
        const packet = new Packet();
        packet.header.rd = recursive ? 1 : 0;
        if (clientIp !== null) {
            packet.additionals.push(EDNS.createResource([new EdnsECS(clientIp)]));
        }
        packet.questions.push(new PacketQuestion(name, type, cls));
        return packet.toBase64URL();
    }
    static _makeRequest(url, query) {
        return new Promise((resolve, reject) => {
            let turl = url;
            const index = turl.indexOf('://');
            if (index === -1) {
                turl = `https://${turl}`;
            }
            const parsed = new URL(turl);
            if (!parsed.pathname || parsed.pathname === '/') {
                turl = turl.replace(/\/?$/u, '/dns-query?dns={query}');
            }
            turl = turl.replace('{query}', query);
            const requestHeaders = { accept: 'application/dns-message' };
            if (parsed.protocol === 'h2:') {
                const client = http2.connect(turl.replace('h2:', 'https:'));
                const parsedUrl = new URL(turl);
                const req = client.request({
                    ':path': `${parsedUrl.pathname}${parsedUrl.search}`,
                    ':method': 'GET',
                    ...requestHeaders
                });
                req.on('response', (headers) => {
                    client.close();
                    const response = {
                        statusCode: headers[':status'],
                        on(event, cb) {
                            req.on(event, cb);
                            return response;
                        }
                    };
                    resolve(response);
                });
                req.on('error', (err) => {
                    client.close();
                    reject(err);
                });
                req.end();
            }
            else {
                const get = parsed.protocol === 'http:' ? http.get : https.get;
                const req = get(turl, { headers: requestHeaders }, (res) => resolve(res));
                req.on('error', reject);
            }
        });
    }
    static _readStream(res) {
        return new Promise((resolve, reject) => {
            const chunks = [];
            res
                .on('error', (err) => reject(err))
                .on('data', (...args) => chunks.push(args[0]))
                .on('end', () => {
                const data = Buffer.concat(chunks);
                if (res.statusCode !== 200) {
                    reject(new Error(`HTTP ${res.statusCode}: ${data.toString()}`));
                    return;
                }
                resolve(data);
            });
        });
    }
    static request(option) {
        return async (name, type, cls, options) => {
            let clientIp = null;
            let recursive = true;
            if (options) {
                if (options.clientIp !== undefined) {
                    clientIp = options.clientIp;
                }
                if (options.recursive !== undefined) {
                    recursive = options.recursive;
                }
            }
            const query = DohClient.buildQuery(name, type, cls, clientIp, recursive);
            const response = await DohClient._makeRequest(option.dns, query);
            const data = await DohClient._readStream(response);
            return Packet.parse(data);
        };
    }
}
//# sourceMappingURL=DohClient.js.map