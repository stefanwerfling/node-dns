import http from 'http';
import https from 'https';
import http2 from 'http2';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {EDNS, EdnsECS} from '../Packet/Types/EDNS.js';
import {AClient} from './AClient.js';
import {ClientOptions} from './ClientOptions.js';
import {ClientRequest} from './ClientRequest.js';

/**
 * HTTP response-like object
 */
interface HttpResponse {
    statusCode?: number;
    on(event: string, cb: (...args: unknown[]) => void): HttpResponse;
}

/**
 * DohClient
 */
export class DohClient extends AClient {

    /**
     * Build a query in base64url format
     * @param {string} name
     * @param {PacketTypes|number} type
     * @param {PacketClass} cls
     * @param {string|null} clientIp
     * @param {boolean} recursive
     * @return {string}
     */
    public static buildQuery(
        name: string,
        type: PacketTypes|number,
        cls: PacketClass,
        clientIp: string|null = null,
        recursive: boolean = true
    ): string {
        const packet = new Packet();
        packet.header.rd = recursive ? 1 : 0;

        if (clientIp !== null) {
            packet.additionals.push(
                EDNS.createResource([new EdnsECS(clientIp)])
            );
        }

        packet.questions.push(new PacketQuestion(name, type, cls));

        return packet.toBase64URL();
    }

    /**
     * Make an HTTP request
     * @param {string} url
     * @param {string} query
     * @return {Promise<HttpResponse>}
     */
    private static _makeRequest(url: string, query: string): Promise<HttpResponse> {
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

            const requestHeaders = {accept: 'application/dns-message'};

            if (parsed.protocol === 'h2:') {
                const client = http2.connect(turl.replace('h2:', 'https:'));
                const parsedUrl = new URL(turl);
                const req = client.request({
                    ':path': `${parsedUrl.pathname}${parsedUrl.search}`,
                    ':method': 'GET',
                    ...requestHeaders
                });

                req.on('response', (headers: http2.IncomingHttpHeaders & http2.IncomingHttpStatusHeader) => {
                    client.close();

                    const response: HttpResponse = {
                        statusCode: headers[':status'],
                        on: (event: string, cb: (...args: unknown[]) => void): HttpResponse => {
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
            } else {
                const get = parsed.protocol === 'http:' ? http.get : https.get;
                const req = get(turl, {headers: requestHeaders}, (res) => resolve(res));

                req.on('error', reject);
            }
        });
    }

    /**
     * Read an HTTP response stream
     * @param {HttpResponse} res
     * @return {Promise<Buffer>}
     */
    private static _readStream(res: HttpResponse): Promise<Buffer> {
        return new Promise((resolve, reject) => {
            const chunks: Buffer[] = [];

            res
            .on('error', (err: unknown) => reject(err))
            .on('data', (...args: unknown[]) => chunks.push(args[0] as Buffer))
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

    /**
     * Create a resolver function
     * @param {ClientOptions} option
     * @return {ClientRequest}
     */
    public static request(option: ClientOptions): ClientRequest {
        return async(name, type, cls, options): Promise<Packet> => {
            let clientIp: string|null = null;
            let recursive: boolean = true;

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