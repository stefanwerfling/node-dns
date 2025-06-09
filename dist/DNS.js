import EventEmitter from 'events';
import { ClientOptionsProtocol } from './Client/ClientOptions.js';
import { TCPClient } from './Client/TCPClient.js';
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
            if (options.recursive) {
                this.recursive = options.recursive;
            }
            if (options.resolverProtocol) {
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
    async resolve(domain, type = PacketTypes.ANY, cls = PacketClass.IN, options) {
        const port = this.port;
        const nameServers = this.nameServers;
        let createResolver = TCPClient;
        switch (this.resolverProtocol) {
            case ClientOptionsProtocol.tls:
            case ClientOptionsProtocol.tcp:
                createResolver = TCPClient;
        }
        return Promise.race(nameServers.map(address => {
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
}
//# sourceMappingURL=DNS.js.map