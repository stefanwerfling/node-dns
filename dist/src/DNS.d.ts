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
    resolve(domain: string, type?: PacketTypes, cls?: PacketClass, options?: ClientRequestOptions): Promise<Packet>;
    resolveA(domain: string, clientIp?: string): Promise<Packet>;
}
