import EventEmitter from 'events';
import http from 'http';
import https from 'https';
import { URL } from 'url';
import { debuglog } from 'util';
import { Packet } from '../Packet/Packet.js';
const debug = debuglog('dns2-server');
export class DohServer extends EventEmitter {
    _server;
    _cors = true;
    _port = 8080;
    _preRequest;
    constructor(options = null) {
        super();
        let soptions;
        const dohOpts = options?.doh;
        if (typeof dohOpts === 'object') {
            soptions = dohOpts.options;
            if (dohOpts.cors !== undefined) {
                this._cors = dohOpts.cors;
            }
            if (dohOpts.preRequest) {
                this._preRequest = dohOpts.preRequest;
            }
        }
        if (soptions) {
            this._server = https.createServer(soptions);
        }
        else {
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
    async _handleRequest(client, res) {
        try {
            const { method, url, headers } = client;
            const { pathname, searchParams: query } = new URL(url ? url : '', 'http://unused/');
            if (this._cors === true) {
                res.setHeader('Access-Control-Allow-Origin', '*');
            }
            else if (typeof this._cors === 'string') {
                res.setHeader('Access-Control-Allow-Origin', this._cors);
                res.setHeader('Vary', 'Origin');
            }
            else if (typeof this._cors === 'function') {
                const isAllowed = await this._cors(headers.origin);
                res.setHeader('Access-Control-Allow-Origin', isAllowed && headers.origin ? headers.origin : 'false');
                res.setHeader('Vary', 'Origin');
            }
            debug('request', method, url);
            if (method !== 'GET' && method !== 'POST') {
                res.writeHead(405, { 'Content-Type': 'text/plain' });
                res.write('405 Method not allowed\n');
                res.end();
                return;
            }
            if (pathname !== '/dns-query') {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.write('404 Not Found\n');
                res.end();
                return;
            }
            const contentType = headers.accept;
            if (contentType !== 'application/dns-message') {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                res.write('400 Bad Request: Illegal content type\n');
                res.end();
                return;
            }
            let queryData;
            if (method === 'GET') {
                const dns = query.get('dns');
                if (!dns) {
                    res.writeHead(400, { 'Content-Type': 'text/plain' });
                    res.write('400 Bad Request: No query defined\n');
                    res.end();
                    return;
                }
                const base64 = DohServer.decodeBase64URL(dns);
                if (!base64) {
                    res.writeHead(400, { 'Content-Type': 'text/plain' });
                    res.write('400 Bad Request: Invalid query data\n');
                    res.end();
                    return;
                }
                queryData = Buffer.from(base64, 'base64');
            }
            else if (method === 'POST') {
                queryData = Buffer.from(await DohServer.readStream(client));
            }
            if (queryData === undefined) {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                res.write('400 Bad Request: Invalid query data\n');
                res.end();
                return;
            }
            let emitClient = client;
            if (this._preRequest) {
                const result = await this._preRequest.process(queryData, client);
                queryData = result.data;
                if (result.client) {
                    emitClient = result.client;
                }
            }
            const message = Packet.parse(queryData);
            this.emit('request', message, this._response.bind(this, res), emitClient);
        }
        catch (e) {
            this.emit('requestError', e);
            res.destroy();
        }
    }
    _response(res, message) {
        debug('response');
        res.setHeader('Content-Type', 'application/dns-message');
        res.writeHead(200);
        res.end(message.toBuffer());
    }
    listen(port, address) {
        const listenPort = port === undefined ? this._port : port;
        this._server.listen(listenPort, address);
    }
    address() {
        return this._server.address();
    }
    close() {
        this._server.close();
    }
    static decodeBase64URL(str) {
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
    static async readStream(client) {
        return new Promise((resolve, reject) => {
            let tbuffer = '';
            client
                .on('error', reject)
                .on('data', chunk => { tbuffer += chunk; })
                .on('end', () => resolve(tbuffer));
        });
    }
}
//# sourceMappingURL=DohServer.js.map