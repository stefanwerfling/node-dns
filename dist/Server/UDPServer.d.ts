import dgram from 'dgram';
import { Buffer } from 'buffer';
import { AddressInfo } from 'net';
import { Rrl, RrlDecision } from '../Lib/Rrl.js';
import { Packet } from '../Packet/Packet.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { EdnsCookie } from '../Packet/Types/EdnsCookie.js';
import { ServerCookieOptions, ServerOptions } from './ServerOptions.js';
import { ServerPreRequest } from './ServerPreRequest.js';
export type CookieRejectionReason = 'no-server-cookie' | 'invalid-cookie' | 'no-cookie-strict';
export type UDPSendable = Packet | Packet[] | Buffer;
export type UDPRequestListener = (msg: Packet, send: (msg: UDPSendable) => Promise<Buffer | void>, rinfo: dgram.RemoteInfo, rawRequest: Buffer) => void;
export declare class UDPServer {
    protected _socket: dgram.Socket;
    protected _preRequest?: ServerPreRequest<dgram.RemoteInfo>;
    protected _rrl?: Rrl;
    protected _cookies?: Required<Omit<ServerCookieOptions, 'secret'>> & {
        secret: Buffer;
    };
    constructor(options?: ServerOptions | null);
    on(event: 'request', listener: UDPRequestListener): this;
    on(event: 'requestError', listener: (err: unknown) => void): this;
    on(event: 'rateLimited', listener: (msg: Packet, rinfo: dgram.RemoteInfo, decision: Exclude<RrlDecision, 'allow'>) => void): this;
    on(event: 'cookieRejected', listener: (msg: Packet, rinfo: dgram.RemoteInfo, reason: CookieRejectionReason) => void): this;
    once(event: string, listener: (...args: any[]) => void): this;
    protected _handle(data: Buffer, rinfo: dgram.RemoteInfo): Promise<void>;
    protected _evaluateCookie(message: Packet, clientAddress: string): {
        action: 'allow' | 'badcookie' | 'refused';
        reason?: CookieRejectionReason;
        clientCookie: Buffer | null;
        freshServerCookie: Buffer | null;
    };
    protected _sendCookieReject(rinfo: dgram.RemoteInfo, request: Packet, rcode: number, clientCookie: Buffer | null, freshServerCookie: Buffer | null): Promise<Buffer | void>;
    protected _cookieAwareSend(rinfo: dgram.RemoteInfo, clientCookie: Buffer, freshServerCookie: Buffer): (msg: UDPSendable) => Promise<Buffer | void>;
    protected _buildCookieOpt(clientCookie: Buffer | null, serverCookie: Buffer | null, extTtl: number): PacketResource;
    protected _attachOrReplaceCookieOpt(response: Packet, clientCookie: Buffer, serverCookie: Buffer): void;
    protected static _findCookieOption(message: Packet): EdnsCookie | null;
    protected _sendTruncated(rinfo: dgram.RemoteInfo, request: Packet): Promise<Buffer | void>;
    protected _response(rinfo: dgram.RemoteInfo, message: UDPSendable): Promise<Buffer | void>;
    listen(port: number, address?: string): Promise<void>;
    close(callback?: () => void): void;
    address(): AddressInfo;
}
