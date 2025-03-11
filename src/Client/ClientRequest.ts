import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketTypes} from '../Packet/PacketTypes.js';

/**
 * Client Request options
 */
export type ClientRequestOptions = {
    clientIp?: string;
    recursive?: boolean;
};

/**
 * Client Request
 */
export type ClientRequest = (
    name: string,
    type: PacketTypes,
    cls: PacketClass,
    options?: ClientRequestOptions
) => Promise<Packet>;