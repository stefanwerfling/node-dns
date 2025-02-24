import EventEmitter from 'events';

/**
 * DNSOptions
 */
export type DNSOptions = {
    port?: number;
    retries?: number;
    timeout?: number;
    recursive?: boolean;
    resolverProtocol?: string;
    nameServers?: string[];
    rootServers?: string[];
};

/**
 * [DNS description]
 * @docs https://tools.ietf.org/html/rfc1034
 * @docs https://tools.ietf.org/html/rfc1035
 */
export class DNS extends EventEmitter {

    /**
     * options
     * @protected
     */
    protected _options: DNSOptions;

    /**
     * constructor
     * @param options
     */
    public constructor(options?: DNSOptions) {
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

    public async query(): Promise<void> {
        return;
    }

}