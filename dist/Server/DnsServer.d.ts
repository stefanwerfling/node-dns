import EventEmitter from 'events';
import { AddressInfo } from 'net';
import { DohServer } from './DohServer.js';
import { ServerOptions } from './ServerOptions.js';
import { TCPServer } from './TCPServer.js';
import { TLSServer } from './TLSServer.js';
import { UDPServer } from './UDPServer.js';
export type DnsServerAddresses = {
    udp?: AddressInfo;
    tcp?: AddressInfo | string | null;
    tls?: AddressInfo | string | null;
    doh?: AddressInfo | string | null;
};
export type DnsServerListenOptions = {
    udp?: number | {
        port?: number;
        address?: string;
    };
    tcp?: number | {
        port?: number;
        address?: string;
    };
    tls?: number | {
        port?: number;
        address?: string;
    };
    doh?: number | {
        port?: number;
        address?: string;
    };
};
export declare class DnsServer extends EventEmitter {
    protected _udp?: UDPServer;
    protected _tcp?: TCPServer;
    protected _tls?: TLSServer;
    protected _doh?: DohServer;
    protected _closed: Promise<void>;
    protected _listening: Promise<DnsServerAddresses>;
    constructor(options?: ServerOptions);
    addresses(): DnsServerAddresses;
    listen(options?: DnsServerListenOptions): Promise<DnsServerAddresses>;
    close(): Promise<void>;
}
