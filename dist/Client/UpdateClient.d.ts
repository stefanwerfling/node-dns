import { Buffer } from 'buffer';
import { Packet } from '../Packet/Packet.js';
import { UpdateBuilder } from '../Packet/Update.js';
import { AClient } from './AClient.js';
import { ClientOptionsProtocol } from './ClientOptions.js';
export type UpdateClientOptions = {
    dns: string;
    port?: number;
    protocol?: ClientOptionsProtocol.udp | ClientOptionsProtocol.tcp | ClientOptionsProtocol.tls;
};
export declare class UpdateClient extends AClient {
    static request(option: UpdateClientOptions): (msg: UpdateBuilder | Packet) => Promise<Packet>;
    protected static _sendUdp(host: string, port: number, query: Buffer): Promise<Packet>;
    protected static _sendStream(host: string, port: number, query: Buffer, useTls: boolean): Promise<Packet>;
}
