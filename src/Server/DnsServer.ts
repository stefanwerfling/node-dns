import EventEmitter from 'events';
import {AddressInfo} from 'net';
import {Packet} from '../Packet/Packet.js';
import {DohServer} from './DohServer.js';
import {ServerOptions} from './ServerOptions.js';
import {TCPServer} from './TCPServer.js';
import {UDPServer} from './UDPServer.js';

/**
 * Server address map
 */
export type DnsServerAddresses = {
    udp?: AddressInfo;
    tcp?: AddressInfo|string|null;
    doh?: AddressInfo|string|null;
};

/**
 * Listen options
 */
export type DnsServerListenOptions = {
    udp?: number | {port?: number; address?: string;};
    tcp?: number | {port?: number; address?: string;};
    doh?: number | {port?: number; address?: string;};
};

/**
 * DnsServer - Combined server that manages UDP, TCP and DoH
 */
export class DnsServer extends EventEmitter {

    protected _udp?: UDPServer;
    protected _tcp?: TCPServer;
    protected _doh?: DohServer;

    protected _closed: Promise<void>;
    protected _listening: Promise<DnsServerAddresses>;

    public constructor(options: ServerOptions = {}) {
        super();

        const closePromises: Promise<void>[] = [];
        const listenPromises: Promise<void>[] = [];

        if (options.doh) {
            this._doh = new DohServer(options);

            this._doh.on('error', (error: Error) => this.emit('error', error, 'doh'));
            this._doh.on('request', (request: Packet, send: unknown, client: unknown) => this.emit('request', request, send, client));
            this._doh.on('requestError', (error: unknown) => this.emit('requestError', error));

            closePromises.push(new Promise<void>((resolve) => { this._doh!.on('close', resolve); }));
            listenPromises.push(new Promise<void>((resolve) => { this._doh!.on('listening', resolve); }));
        }

        if (options.tcp) {
            this._tcp = new TCPServer(options);

            this._tcp.on('requestError', (error: Error) => this.emit('error', error, 'tcp'));
            this._tcp.on('request', (request: Packet, send: unknown, client: unknown) => this.emit('request', request, send, client));

            closePromises.push(new Promise<void>((resolve) => { this._tcp!.once('close', resolve); }));
            listenPromises.push(new Promise<void>((resolve) => { this._tcp!.once('listening', resolve); }));
        }

        if (options.udp) {
            const udpOptions: ServerOptions|null = typeof options.udp === 'object' ? options : null;

            this._udp = new UDPServer(udpOptions);

            this._udp.on('requestError', (error: unknown) => this.emit('requestError', error));
            this._udp.on('request', (request, send, rinfo) => this.emit('request', request, send, rinfo));

            closePromises.push(new Promise<void>((resolve) => { this._udp!.once('close', resolve); }));
            listenPromises.push(new Promise<void>((resolve) => { this._udp!.once('listening', resolve); }));
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

    /**
     * Get addresses of all running servers
     * @return {DnsServerAddresses}
     */
    public addresses(): DnsServerAddresses {
        const addresses: DnsServerAddresses = {};

        if (this._udp) {
            addresses.udp = this._udp.address();
        }

        if (this._tcp) {
            addresses.tcp = this._tcp.address();
        }

        if (this._doh) {
            addresses.doh = this._doh.address();
        }

        return addresses;
    }

    /**
     * Start listening on all servers
     * @param {DnsServerListenOptions} options
     * @return {Promise<DnsServerAddresses>}
     */
    public listen(options: DnsServerListenOptions = {}): Promise<DnsServerAddresses> {
        if (this._udp) {
            const opt = options.udp;

            if (typeof opt === 'object' && opt.port !== undefined) {
                this._udp.listen(opt.port, opt.address);
            } else if (typeof opt === 'number') {
                this._udp.listen(opt);
            } else {
                this._udp.listen(0);
            }
        }

        if (this._tcp) {
            const opt = options.tcp;

            if (typeof opt === 'object' && opt.port !== undefined) {
                this._tcp.listen({port: opt.port, host: opt.address});
            } else if (typeof opt === 'number') {
                this._tcp.listen(opt);
            } else {
                this._tcp.listen(0);
            }
        }

        if (this._doh) {
            const opt = options.doh;

            if (typeof opt === 'object' && opt.port !== undefined) {
                this._doh.listen(opt.port, opt.address);
            } else if (typeof opt === 'number') {
                this._doh.listen(opt);
            } else {
                this._doh.listen();
            }
        }

        return this._listening;
    }

    /**
     * Close all servers
     * @return {Promise<void>}
     */
    public close(): Promise<void> {
        if (this._udp) {
            this._udp.close();
        }

        if (this._tcp) {
            this._tcp.close();
        }

        if (this._doh) {
            this._doh.close();
        }

        return this._closed;
    }

}