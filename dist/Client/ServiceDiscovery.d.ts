import { PacketResource } from '../Packet/PacketResource.js';
import { TXT } from '../Packet/Types/TXT.js';
import { MdnsClient, MdnsClientOptions } from './MdnsClient.js';
export type ServiceInstance = {
    name: string;
    host?: string;
    port?: number;
    priority?: number;
    weight?: number;
    txt?: Record<string, string | true>;
    addresses: string[];
};
export type ServiceDiscoveryOptions = {
    serviceType: string;
    domain?: string;
    timeoutMs?: number;
    resolveMissing?: boolean;
    mdns?: MdnsClientOptions;
};
export declare class ServiceDiscovery {
    static browse(options: ServiceDiscoveryOptions): Promise<ServiceInstance[]>;
    static resolveInstance(instanceName: string, options?: Omit<ServiceDiscoveryOptions, 'serviceType' | 'domain'>): Promise<ServiceInstance>;
    protected static _foldRecords(records: PacketResource[], byInstance: Map<string, ServiceInstance>, cnames: Map<string, string[]>): void;
    protected static _fillSrv(resolve: ReturnType<typeof MdnsClient.request>, inst: ServiceInstance): Promise<void>;
    protected static _fillTxt(resolve: ReturnType<typeof MdnsClient.request>, inst: ServiceInstance): Promise<void>;
    protected static _fillAddresses(resolve: ReturnType<typeof MdnsClient.request>, inst: ServiceInstance): Promise<void>;
    protected static _normalize(name: string): string;
    protected static _parseTxt(txt: TXT): Record<string, string | true>;
}
