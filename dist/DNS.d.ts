import EventEmitter from 'events';
export type DNSOptions = {
    port?: number;
    retries?: number;
    timeout?: number;
    recursive?: boolean;
    resolverProtocol?: string;
    nameServers?: string[];
    rootServers?: string[];
};
export declare class DNS extends EventEmitter {
    protected _options: DNSOptions;
    constructor(options?: DNSOptions);
    query(): Promise<void>;
}
