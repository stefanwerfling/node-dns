import EventEmitter from 'events';
import {ClientCreateResolver} from './Client/ClientCreateResolver.js';
import {ClientOptionsProtocol} from './Client/ClientOptions.js';
import {ClientRequest, ClientRequestOptions} from './Client/ClientRequest.js';
import {DohClient} from './Client/DohClient.js';
import {TCPClient} from './Client/TCPClient.js';
import {UDPClient} from './Client/UDPClient.js';
import {Packet} from './Packet/Packet.js';
import {PacketClass} from './Packet/PacketClass.js';
import {PacketTypes} from './Packet/PacketTypes.js';

/**
 * DNSOptions
 */
export type DNSOptions = {
    port?: number;
    retries?: number;
    timeout?: number;
    recursive?: boolean;
    resolverProtocol?: ClientOptionsProtocol;
    nameServers?: string[];
    rootServers?: string[];
};

/**
 * [DNS description]
 * @docs https://tools.ietf.org/html/rfc1034
 * @docs https://tools.ietf.org/html/rfc1035
 */
export class DNS extends EventEmitter {

    public port: number;

    public retries: number;

    public timeout: number;

    public recursive: boolean;

    public resolverProtocol: ClientOptionsProtocol;

    public nameServers: string[];

    public rootServers: string[];

    /**
     * constructor
     * @param options
     */
    public constructor(options?: DNSOptions) {
        super();

        // set defaults ------------------------------------------------------------------------------------------------

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

        // overwrite options -------------------------------------------------------------------------------------------

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

    /**
     * Get the resolver class for a protocol
     * @param {ClientOptionsProtocol} protocol
     * @return {ClientCreateResolver}
     */
    private _getResolver(protocol: ClientOptionsProtocol): ClientCreateResolver {
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

    /**
     * Resolve
     * @param {string} domain
     * @param {PacketTypes} type
     * @param {PacketClass} cls
     * @param {[ClientRequestOptions]} options
     * @return {Packet}
     */
    /* eslint-disable default-param-last */
    public async resolve(
        domain: string,
        type: PacketTypes = PacketTypes.ANY,
        cls: PacketClass = PacketClass.IN,
        options?: ClientRequestOptions
    ): Promise<Packet> {
        /* eslint-enable default-param-last */
        const port = this.port;
        const nameServers = this.nameServers;
        const createResolver = this._getResolver(this.resolverProtocol);

        return Promise.race(nameServers.map((address) => {
            const resolve: ClientRequest = createResolver.request({
                dns: address,
                port: port
            });

            return resolve(domain, type, cls, options);
        }));
    }

    public async resolveA(domain: string, clientIp?: string): Promise<Packet> {
        return this.resolve(domain, PacketTypes.A, undefined, {
            clientIp: clientIp
        });
    }

    public async resolveAAAA(domain: string): Promise<Packet> {
        return this.resolve(domain, PacketTypes.AAAA);
    }

    public async resolveMX(domain: string): Promise<Packet> {
        return this.resolve(domain, PacketTypes.MX);
    }

    public async resolveCNAME(domain: string): Promise<Packet> {
        return this.resolve(domain, PacketTypes.CNAME);
    }

    public async resolvePTR(domain: string): Promise<Packet> {
        return this.resolve(domain, PacketTypes.PTR);
    }

    public async resolveDNSKEY(domain: string): Promise<Packet> {
        return this.resolve(domain, PacketTypes.DNSKEY);
    }

}