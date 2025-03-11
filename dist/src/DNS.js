"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DNS = void 0;
const tslib_1 = require("tslib");
const events_1 = tslib_1.__importDefault(require("events"));
const ClientOptions_js_1 = require("./Client/ClientOptions.js");
const TCPClient_js_1 = require("./Client/TCPClient.js");
const PacketClass_js_1 = require("./Packet/PacketClass.js");
const PacketTypes_js_1 = require("./Packet/PacketTypes.js");
class DNS extends events_1.default {
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
        this.resolverProtocol = ClientOptions_js_1.ClientOptionsProtocol.udp;
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
    async resolve(domain, type = PacketTypes_js_1.PacketTypes.ANY, cls = PacketClass_js_1.PacketClass.IN, options) {
        const port = this.port;
        const nameServers = this.nameServers;
        let createResolver = TCPClient_js_1.TCPClient;
        switch (this.resolverProtocol) {
            case ClientOptions_js_1.ClientOptionsProtocol.tls:
            case ClientOptions_js_1.ClientOptionsProtocol.tcp:
                createResolver = TCPClient_js_1.TCPClient;
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
        return this.resolve(domain, PacketTypes_js_1.PacketTypes.A, undefined, {
            clientIp: clientIp
        });
    }
}
exports.DNS = DNS;
//# sourceMappingURL=DNS.js.map