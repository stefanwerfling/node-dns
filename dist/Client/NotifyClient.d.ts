import { Buffer } from 'buffer';
import { Packet } from '../Packet/Packet.js';
import { SOA } from '../Packet/Types/SOA.js';
import { AClient } from './AClient.js';
import { ClientOptionsProtocol } from './ClientOptions.js';
export type NotifyClientOptions = {
    dns: string;
    port?: number;
    protocol?: ClientOptionsProtocol.udp | ClientOptionsProtocol.tcp | ClientOptionsProtocol.tls;
    sourceSoa?: SOA;
};
export declare class NotifyClient extends AClient {
    static makeQuery(zoneName: string, sourceSoa?: SOA): Packet;
    static request(option: NotifyClientOptions): (zoneName: string) => Promise<Packet>;
    protected static _sendUdp(host: string, port: number, query: Buffer): Promise<Packet>;
    protected static _sendStream(host: string, port: number, query: Buffer, useTls: boolean): Promise<Packet>;
}
