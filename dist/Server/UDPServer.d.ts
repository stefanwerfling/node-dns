import dgram from 'dgram';
import { Packet } from '../Packet/Packet.js';
import { ServerOptions } from './ServerOptions.js';
export type UDPRequestListener = (msg: Packet, send: (msg: Packet | Buffer) => Promise<Buffer | void>, rinfo: dgram.RemoteInfo) => void;
export declare class UDPServer {
    protected _socket: dgram.Socket;
    constructor(options?: ServerOptions);
    on(event: 'request', listener: UDPRequestListener): this;
    on(event: 'requestError', listener: (err: unknown) => void): this;
    once(event: string, listener: (...args: any[]) => void): this;
    protected _handle(data: Buffer, rinfo: dgram.RemoteInfo): void;
    protected _response(rinfo: dgram.RemoteInfo, message: Packet | Buffer): Promise<Buffer | void>;
    listen(port: number, address?: string): Promise<void>;
    close(callback?: () => void): void;
}
