import { Buffer } from 'buffer';
import dgram from 'dgram';
import { AddressInfo } from 'net';
import { Packet } from '../Packet/Packet.js';
import { PacketResource } from '../Packet/PacketResource.js';
export type MdnsSendable = Packet | Buffer;
export type MdnsResponseTarget = 'auto' | 'multicast' | 'unicast';
export type MdnsRequestListener = (msg: Packet, send: (msg: MdnsSendable, target?: MdnsResponseTarget) => Promise<void>, rinfo: dgram.RemoteInfo, rawRequest: Buffer) => void;
export type MdnsServerOptions = {
    multicastAddr?: string;
    port?: number;
    family?: 'udp4' | 'udp6';
    interfaceAddress?: string;
    joinMulticastGroup?: boolean;
    reuseAddr?: boolean;
};
export declare class MdnsServer {
    protected _socket: dgram.Socket;
    protected _multicastAddr: string;
    protected _port: number;
    protected _interfaceAddress?: string;
    protected _joinMulticastGroup: boolean;
    protected _multicastAddress: string;
    constructor(options?: MdnsServerOptions);
    on(event: 'request', listener: MdnsRequestListener): this;
    on(event: 'requestError', listener: (err: unknown) => void): this;
    once(event: string, listener: (...args: any[]) => void): this;
    listen(): Promise<void>;
    announce(records: PacketResource[]): Promise<void>;
    goodbye(records: PacketResource[]): Promise<void>;
    close(callback?: () => void): void;
    address(): AddressInfo;
    protected _handle(data: Buffer, rinfo: dgram.RemoteInfo): void;
    protected _buildSend(request: Packet, rinfo: dgram.RemoteInfo): (msg: MdnsSendable, target?: MdnsResponseTarget) => Promise<void>;
    protected _sendUnsolicited(records: PacketResource[], goodbye: boolean): Promise<void>;
    protected static _anyQuestionHasQu(packet: Packet): boolean;
    protected static _isMulticast(addr: string): boolean;
}
