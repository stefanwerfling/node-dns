import EventEmitter from 'events';
import { ClientOptionsProtocol } from './Client/ClientOptions.js';
import { DohClient } from './Client/DohClient.js';
import { TCPClient } from './Client/TCPClient.js';
import { UDPClient } from './Client/UDPClient.js';
import { PacketClass } from './Packet/PacketClass.js';
import { PacketTypes } from './Packet/PacketTypes.js';
export class DNS extends EventEmitter {
    port;
    retries;
    timeout;
    recursive;
    resolverProtocol;
    nameServers;
    rootServers;
    constructor(options) {
        super();
        this.port = 53;
        this.retries = 3;
        this.timeout = 3;
        this.recursive = true;
        this.resolverProtocol = ClientOptionsProtocol.udp;
        this.nameServers = [
            '8.8.8.8',
            '114.114.114.114'
        ];
        this.rootServers = [
            'a', 'b', 'c', 'd', 'e', 'f',
            'g', 'h', 'i', 'j', 'k', 'l', 'm'
        ].map((x) => `${x}.root-servers.net`);
        if (options) {
            if (options.port) {
                this.port = options.port;
            }
            if (options.retries) {
                this.retries = options.retries;
            }
            if (options.timeout) {
                this.timeout = options.timeout;
            }
            if (options.recursive !== undefined) {
                this.recursive = options.recursive;
            }
            if (options.resolverProtocol !== undefined) {
                this.resolverProtocol = options.resolverProtocol;
            }
            if (options.nameServers) {
                this.nameServers = options.nameServers;
            }
            if (options.rootServers) {
                this.rootServers = options.rootServers;
            }
        }
    }
    _getResolver(protocol) {
        switch (protocol) {
            case ClientOptionsProtocol.udp:
                return UDPClient;
            case ClientOptionsProtocol.doh:
                return DohClient;
            case ClientOptionsProtocol.tls:
            case ClientOptionsProtocol.tcp:
            default:
                return TCPClient;
        }
    }
    async resolve(domain, type = PacketTypes.ANY, cls = PacketClass.IN, options) {
        const port = this.port;
        const nameServers = this.nameServers;
        const createResolver = this._getResolver(this.resolverProtocol);
        return Promise.race(nameServers.map((address) => {
            const resolve = createResolver.request({
                dns: address,
                port: port
            });
            return resolve(domain, type, cls, options);
        }));
    }
    async resolveA(domain, clientIp) {
        return this.resolve(domain, PacketTypes.A, undefined, {
            clientIp: clientIp
        });
    }
    async resolveAAAA(domain) {
        return this.resolve(domain, PacketTypes.AAAA);
    }
    async resolveMX(domain) {
        return this.resolve(domain, PacketTypes.MX);
    }
    async resolveCNAME(domain) {
        return this.resolve(domain, PacketTypes.CNAME);
    }
    async resolvePTR(domain) {
        return this.resolve(domain, PacketTypes.PTR);
    }
    async resolveDNSKEY(domain) {
        return this.resolve(domain, PacketTypes.DNSKEY);
    }
}
//# sourceMappingURL=DNS.js.map