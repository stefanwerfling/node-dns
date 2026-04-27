import http from 'http';
import { Packet } from '../Packet/Packet.js';
export declare const response: Buffer<ArrayBuffer>;
export declare const get: (url: string, options?: http.RequestOptions) => Promise<{
    body: Buffer;
    headers: http.IncomingHttpHeaders;
}>;
export declare const tlsCert: NonSharedBuffer;
export declare const tlsKey: NonSharedBuffer;
export declare const dotQuery: (port: number, name: string) => Promise<Packet>;
