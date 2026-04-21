import { PacketClass } from '../Packet/PacketClass.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { AClient } from './AClient.js';
import { ClientOptions } from './ClientOptions.js';
import { ClientRequest } from './ClientRequest.js';
export declare class DohClient extends AClient {
    static buildQuery(name: string, type: PacketTypes | number, cls: PacketClass, clientIp?: string | null, recursive?: boolean): string;
    private static _makeRequest;
    private static _readStream;
    static request(option: ClientOptions): ClientRequest;
}
