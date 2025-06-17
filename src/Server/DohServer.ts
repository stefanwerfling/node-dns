import EventEmitter from 'events';
import http from 'http';
import https from 'https';
import {AddressInfo} from 'net';
import {URL} from 'url';
import {debuglog} from 'util';
import {Packet} from '../Packet/Packet.js';
import {ServerOptions} from './ServerOptions.js';

const debug = debuglog('dns2-server');

/**
 * Doh server use cors function
 * @return {boolean} is allowed
 */
export type DohServerUseCors = (origin: string|undefined) => Promise<boolean>;

/**
 * Doh Server
 */
export class DohServer extends EventEmitter {

    /**
     * HTTP/HTTPS Server
     * @protected
     */
    protected _server: http.Server|https.Server;

    /**
     * Use cors
     * @protected
     */
    protected _cors: boolean|string|DohServerUseCors = true;

    /**
     * Port
     * @protected
     */
    protected _port: number = 8080;

    /**
     * Constructor
     * @param {ServerOptions|null} options
     */
    public constructor(options: ServerOptions|null = null) {
        super();

        let soptions: https.ServerOptions | undefined;

        if (options?.doh) {
            soptions = options?.doh?.options ? options.doh.options : undefined;
        }

        if (soptions) {
            this._server = https.createServer(soptions);
        } else {
            this._server = http.createServer();
        }

        this._server.on('request', this._handleRequest.bind(this));
        this._server.on('listening', () => this.emit('listening', this.address()));
        this._server.on('error', error => this.emit('error', error));
        this._server.on('close', () => {
            this._server.removeAllListeners();
            this.emit('close');
        });
    }

    /**
     * Request handler
     * @param {http.IncomingMessage} client
     * @param {http.ServerResponse} res
     * @protected
     */
    protected async _handleRequest(client: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
        try {
            const { method, url, headers } = client;
            const { pathname, searchParams: query } = new URL(url ? url : '', 'http://unused/');

            if (this._cors === true) {
                res.setHeader('Access-Control-Allow-Origin', '*');
            } else if (typeof this._cors === 'string') {
                res.setHeader('Access-Control-Allow-Origin', this._cors);
                res.setHeader('Vary', 'Origin');
            } else if (typeof this._cors === 'function') {
                const isAllowed = await this._cors(headers.origin);

                res.setHeader('Access-Control-Allow-Origin', isAllowed && headers.origin ? headers.origin : 'false');
                res.setHeader('Vary', 'Origin');
            }

            debug('request', method, url);

            // We are only handling get and post as reqired by rfc
            if (method !== 'GET' && method !== 'POST') {
                res.writeHead(405, { 'Content-Type': 'text/plain' });
                res.write('405 Method not allowed\n');
                res.end();
                return;
            }

            // Check so the uri is correct
            if (pathname !== '/dns-query') {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.write('404 Not Found\n');
                res.end();
                return;
            }

            const contentType = headers.accept;

            // Make sure the requestee is requesting the correct content type
            if (contentType !== 'application/dns-message') {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                res.write('400 Bad Request: Illegal content type\n');
                res.end();
                return;
            }

            let queryData;

            if (method === 'GET') {
                // Parse query string for the request data
                const dns = query.get('dns');

                if (!dns) {
                    res.writeHead(400, { 'Content-Type': 'text/plain' });
                    res.write('400 Bad Request: No query defined\n');
                    res.end();
                    return;
                }

                // Decode from Base64Url Encoding
                const base64 = DohServer.decodeBase64URL(dns);

                if (!base64) {
                    res.writeHead(400, { 'Content-Type': 'text/plain' });
                    res.write('400 Bad Request: Invalid query data\n');
                    res.end();
                    return;
                }

                queryData = Buffer.from(base64, 'base64');
            } else if (method === 'POST') {
                queryData = Buffer.from(await DohServer.readStream(client));
            }

            if (queryData === undefined) {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                res.write('400 Bad Request: Invalid query data\n');
                res.end();
                return;
            }

            // Parse DNS query and Raise event.
            const message = Packet.parse(queryData);

            this.emit('request', message, this._response.bind(this, res), client);
        } catch (e) {
            this.emit('requestError', e);
            res.destroy();
        }
    }

    /**
     * Response
     * @param {http.ServerResponse} res
     * @param {Packet} message
     * @protected
     */
    protected _response(res: http.ServerResponse, message: Packet): void {
        debug('response');

        res.setHeader('Content-Type', 'application/dns-message');
        res.writeHead(200);
        res.end(message.toBuffer());
    }

    /**
     * Listen
     * @param {[number]} port
     * @param {[string]} address
     */
    public listen(port?: number, address?: string): void {
        this._server.listen(port || this._port, address);
    }

    /**
     * Return server address
     * @return {AddressInfo|string|null}
     */
    public address(): AddressInfo|string|null {
        return this._server.address();
    }

    /**
     * Close
     */
    public close(): void {
        this._server.close();
    }

    /**
     * decode base64 url
     * @param {string} str
     * @return {string|null}
     */
    public static decodeBase64URL(str: string): string|null {
        let queryData = str
        .replace(/-/gu, '+')
        .replace(/_/gu, '/');

        const pad = queryData.length % 4;

        if (pad === 1) {
            return null;
        }

        if (pad) {
            queryData += new Array(5 - pad).join('=');
        }

        return queryData;
    }

    /**
     * Read the stream by client (post)
     * @param {client: http.IncomingMessage} client
     * @return {string}
     */
    public static async readStream(client: http.IncomingMessage): Promise<string> {
        return new Promise((resolve, reject) => {
            let tbuffer = '';

            client
            .on('error', reject)
            .on('data', chunk => { tbuffer += chunk; })
            .on('end', () => resolve(tbuffer));
        });
    }

}