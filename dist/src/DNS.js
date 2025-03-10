"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DNS = void 0;
const tslib_1 = require("tslib");
const events_1 = tslib_1.__importDefault(require("events"));
class DNS extends events_1.default {
    _options;
    constructor(options) {
        super();
        this._options = {
            port: 53,
            retries: 3,
            timeout: 3,
            recursive: true,
            resolverProtocol: 'UDP',
            nameServers: [
                '8.8.8.8',
                '114.114.114.114'
            ],
            rootServers: [
                'a', 'b', 'c', 'd', 'e', 'f',
                'g', 'h', 'i', 'j', 'k', 'l', 'm'
            ].map((x) => `${x}.root-servers.net`)
        };
        if (options) {
            if (options.port) {
                this._options.port = options.port;
            }
            if (options.retries) {
                this._options.retries = options.retries;
            }
            if (options.timeout) {
                this._options.timeout = options.timeout;
            }
            if (options.recursive) {
                this._options.recursive = options.recursive;
            }
            if (options.resolverProtocol) {
                this._options.resolverProtocol = options.resolverProtocol;
            }
            if (options.nameServers) {
                this._options.nameServers = options.nameServers;
            }
            if (options.rootServers) {
                this._options.rootServers = options.rootServers;
            }
        }
    }
    async query() {
        return;
    }
}
exports.DNS = DNS;
//# sourceMappingURL=DNS.js.map