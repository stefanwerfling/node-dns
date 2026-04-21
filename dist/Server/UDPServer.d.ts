import dgram from 'dgram';
import { Buffer } from 'buffer';
import { AddressInfo } from 'net';
import { Packet } from '../Packet/Packet.js';
import { ServerOptions } from './ServerOptions.js';
export type UDPRequestListener = (msg: Packet, send: (msg: Packet | Buffer) => Promise<Buffer | void>, rinfo: dgram.RemoteInfo) => void;
export type UDPRequestPre = (data: Buffer, rinfo: dgram.RemoteInfo) => Promise<Buffer>;
export declare class UDPServer {
    protected _socket: dgram.Socket;
    protected _preRequest?: UDPRequestPre;
    constructor(options?: ServerOptions | null);
    on(event: 'request', listener: UDPRequestListener): this;
    on(event: 'requestError', listener: (err: unknown) => void): this;
    once(event: string, listener: (...args: any[]) => void): this;
    protected _handle(data: Buffer, rinfo: dgram.RemoteInfo): Promise<void>;
    protected _response(rinfo: dgram.RemoteInfo, message: Packet | Buffer): Promise<Buffer | void>;
    listen(port: number, address?: string): Promise<void>;
    close(callback?: () => void): void;
    address(): AddressInfo;
    setPreRequest(preReq: UDPRequestPre): void;
}
