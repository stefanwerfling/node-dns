import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { AClient } from './AClient.js';
import { ClientOptions } from './ClientOptions.js';
import { ClientRequest } from './ClientRequest.js';
export declare class UDPClient extends AClient {
    static makeQuery(name: string, type: PacketTypes | number, cls: PacketClass, clientIp?: string | null, recursive?: boolean): Packet;
    static request(option: ClientOptions): ClientRequest;
}
