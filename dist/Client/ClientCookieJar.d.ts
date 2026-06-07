import { Buffer } from 'buffer';
import { Packet } from '../Packet/Packet.js';
import { EdnsCookie } from '../Packet/Types/EdnsCookie.js';
export type ClientCookieEntry = {
    clientCookie: Buffer;
    serverCookie: Buffer | null;
};
export declare class ClientCookieJar {
    protected _entries: Map<string, ClientCookieEntry>;
    static key(host: string, port: number): string;
    getOrCreate(host: string, port: number): ClientCookieEntry;
    peek(host: string, port: number): ClientCookieEntry | null;
    learn(host: string, port: number, serverCookie: Buffer | null): void;
    forget(host: string, port: number): void;
    clear(): void;
    size(): number;
    attachTo(query: Packet, host: string, port: number): void;
    learnFromResponse(response: Packet, host: string, port: number): EdnsCookie | null;
    static findCookieOption(message: Packet): EdnsCookie | null;
    static extendedRcode(response: Packet): number;
    static isBadCookie(response: Packet): boolean;
}
