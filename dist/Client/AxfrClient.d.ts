import { Buffer } from 'buffer';
import tcp from 'net';
import tls from 'tls';
import { PacketResource } from '../Packet/PacketResource.js';
import { AClient } from './AClient.js';
import { ClientOptionsProtocol } from './ClientOptions.js';
export type AxfrClientOptions = {
    dns: string;
    port?: number;
    protocol?: ClientOptionsProtocol.tcp | ClientOptionsProtocol.tls;
};
export type AxfrResult = {
    soa: PacketResource;
    records: PacketResource[];
};
export declare class AxfrClient extends AClient {
    static makeQuery(zoneName: string): Buffer;
    static connect(option: AxfrClientOptions): tcp.Socket | tls.TLSSocket;
    static request(option: AxfrClientOptions): (zoneName: string) => Promise<AxfrResult>;
}
