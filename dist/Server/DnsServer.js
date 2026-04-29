import EventEmitter from 'events';
import { DohServer } from './DohServer.js';
import { TCPServer } from './TCPServer.js';
import { TLSServer } from './TLSServer.js';
import { UDPServer } from './UDPServer.js';
export class DnsServer extends EventEmitter {
    _udp;
    _tcp;
    _tls;
    _doh;
    _closed;
    _listening;
    constructor(options = {}) {
        super();
        const closePromises = [];
        const listenPromises = [];
        if (options.doh) {
            this._doh = new DohServer(options);
            this._doh.on('error', (error) => this.emit('error', error, 'doh'));
            this._doh.on('request', (request, send, client) => this.emit('request', request, send, client));
            this._doh.on('requestError', (error) => this.emit('requestError', error));
            closePromises.push(new Promise((resolve) => { this._doh.on('close', resolve); }));
            listenPromises.push(new Promise((resolve) => { this._doh.on('listening', resolve); }));
        }
        if (options.tcp) {
            this._tcp = new TCPServer(options);
            this._tcp.on('requestError', (error) => this.emit('error', error, 'tcp'));
            this._tcp.on('request', (request, send, client) => this.emit('request', request, send, client));
            closePromises.push(new Promise((resolve) => { this._tcp.once('close', resolve); }));
            listenPromises.push(new Promise((resolve) => { this._tcp.once('listening', resolve); }));
        }
        if (options.tls) {
            this._tls = new TLSServer(options);
            this._tls.on('requestError', (error) => this.emit('error', error, 'tls'));
            this._tls.on('request', (request, send, client) => this.emit('request', request, send, client));
            closePromises.push(new Promise((resolve) => { this._tls.once('close', resolve); }));
            listenPromises.push(new Promise((resolve) => { this._tls.once('listening', resolve); }));
        }
        if (options.udp) {
            const udpOptions = typeof options.udp === 'object' ? options : null;
            this._udp = new UDPServer(udpOptions);
            this._udp.on('requestError', (error) => this.emit('requestError', error));
            this._udp.on('request', (request, send, rinfo) => this.emit('request', request, send, rinfo));
            this._udp.on('rateLimited', (msg, rinfo, decision) => this.emit('rateLimited', msg, rinfo, decision));
            closePromises.push(new Promise((resolve) => { this._udp.once('close', resolve); }));
            listenPromises.push(new Promise((resolve) => { this._udp.once('listening', resolve); }));
        }
        this._closed = Promise.all(closePromises).then(() => {
            this.emit('close');
        });
        this._listening = Promise.all(listenPromises).then(() => {
            const addresses = this.addresses();
            this.emit('listening', addresses);
            return addresses;
        });
        if (options.handle) {
            this.on('request', options.handle);
        }
    }
    addresses() {
        const addresses = {};
        if (this._udp) {
            addresses.udp = this._udp.address();
        }
        if (this._tcp) {
            addresses.tcp = this._tcp.address();
        }
        if (this._tls) {
            addresses.tls = this._tls.address();
        }
        if (this._doh) {
            addresses.doh = this._doh.address();
        }
        return addresses;
    }
    listen(options = {}) {
        if (this._udp) {
            const opt = options.udp;
            if (typeof opt === 'object' && opt.port !== undefined) {
                this._udp.listen(opt.port, opt.address);
            }
            else if (typeof opt === 'number') {
                this._udp.listen(opt);
            }
            else {
                this._udp.listen(0);
            }
        }
        if (this._tcp) {
            const opt = options.tcp;
            if (typeof opt === 'object' && opt.port !== undefined) {
                this._tcp.listen({ port: opt.port, host: opt.address });
            }
            else if (typeof opt === 'number') {
                this._tcp.listen(opt);
            }
            else {
                this._tcp.listen(0);
            }
        }
        if (this._tls) {
            const opt = options.tls;
            if (typeof opt === 'object' && opt.port !== undefined) {
                this._tls.listen({ port: opt.port, host: opt.address });
            }
            else if (typeof opt === 'number') {
                this._tls.listen(opt);
            }
            else {
                this._tls.listen(0);
            }
        }
        if (this._doh) {
            const opt = options.doh;
            if (typeof opt === 'object' && opt.port !== undefined) {
                this._doh.listen(opt.port, opt.address);
            }
            else if (typeof opt === 'number') {
                this._doh.listen(opt);
            }
            else {
                this._doh.listen();
            }
        }
        return this._listening;
    }
    close() {
        if (this._udp) {
            this._udp.close();
        }
        if (this._tcp) {
            this._tcp.close();
        }
        if (this._tls) {
            this._tls.close();
        }
        if (this._doh) {
            this._doh.close();
        }
        return this._closed;
    }
}
//# sourceMappingURL=DnsServer.js.map