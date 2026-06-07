import { Buffer } from 'buffer';
import { Packet } from '../Packet/Packet.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { EdnsCookie } from '../Packet/Types/EdnsCookie.js';
import { ServerCookieOptions } from './ServerOptions.js';
export declare const BADCOOKIE_RCODE: number;
export type CookieRejectionReason = 'no-server-cookie' | 'invalid-cookie' | 'no-cookie-strict';
export type CookieDecision = {
    action: 'allow';
    clientCookie: Buffer | null;
    freshServerCookie: Buffer | null;
} | {
    action: 'badcookie';
    reason: CookieRejectionReason;
    clientCookie: Buffer;
    freshServerCookie: Buffer;
} | {
    action: 'refused';
    reason: CookieRejectionReason;
};
export declare class CookieGuard {
    protected _config: Required<Omit<ServerCookieOptions, 'secret'>> & {
        secret: Buffer;
    };
    constructor(options: ServerCookieOptions);
    get mode(): 'lenient' | 'strict';
    evaluate(message: Packet, clientAddress: string): CookieDecision;
    buildCookieOpt(clientCookie: Buffer | null, serverCookie: Buffer | null, extTtl: number): PacketResource;
    attachOrReplaceCookieOpt(response: Packet, clientCookie: Buffer, serverCookie: Buffer): void;
    buildBadCookieResponse(request: Packet, clientCookie: Buffer, freshServerCookie: Buffer): Packet;
    buildRefusedResponse(request: Packet): Packet;
    static findCookieOption(message: Packet): EdnsCookie | null;
}
