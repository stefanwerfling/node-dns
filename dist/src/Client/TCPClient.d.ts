import tcp from 'net';
import tls from 'tls';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { AClient } from './AClient.js';
import { ClientOptions, ClientOptionsProtocol } from './ClientOptions.js';
import { ClientRequest } from './ClientRequest.js';
export declare class TCPClient extends AClient {
    static makeQuery(name: string, type: PacketTypes | number, cls: PacketClass, clientIp?: string | null, recursive?: boolean): Buffer;
    static getClient(protocol: ClientOptionsProtocol, host: string, port: number): tcp.Socket | tls.TLSSocket;
    static sendQuery(client: tcp.Socket | tls.TLSSocket, message: Buffer): void;
    static request(option: ClientOptions): ClientRequest;
}
