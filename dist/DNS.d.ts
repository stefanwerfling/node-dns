import EventEmitter from 'events';
import { ClientOptionsProtocol } from './Client/ClientOptions.js';
import { ClientRequestOptions } from './Client/ClientRequest.js';
import { Packet } from './Packet/Packet.js';
import { PacketClass } from './Packet/PacketClass.js';
import { PacketTypes } from './Packet/PacketTypes.js';
export type DNSOptions = {
    port?: number;
    retries?: number;
    timeout?: number;
    recursive?: boolean;
    resolverProtocol?: ClientOptionsProtocol;
    nameServers?: string[];
    rootServers?: string[];
};
export declare class DNS extends EventEmitter {
    port: number;
    retries: number;
    timeout: number;
    recursive: boolean;
    resolverProtocol: ClientOptionsProtocol;
    nameServers: string[];
    rootServers: string[];
    constructor(options?: DNSOptions);
    private _getResolver;
    resolve(domain: string, type?: PacketTypes, cls?: PacketClass, options?: ClientRequestOptions): Promise<Packet>;
    resolveA(domain: string, clientIp?: string): Promise<Packet>;
    resolveAAAA(domain: string): Promise<Packet>;
    resolveMX(domain: string): Promise<Packet>;
    resolveCNAME(domain: string): Promise<Packet>;
    resolvePTR(domain: string): Promise<Packet>;
    resolveDNSKEY(domain: string): Promise<Packet>;
}
