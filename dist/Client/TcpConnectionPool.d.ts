import { Buffer } from 'buffer';
import tls from 'tls';
import type { RecursiveResolverTransport } from '../Resolver/RecursiveResolver.js';
import { AClient } from './AClient.js';
export type TcpConnectionPoolProtocol = 'tcp' | 'tls';
export type TcpConnectionPoolTarget = {
    protocol: TcpConnectionPoolProtocol;
    host: string;
    port: number;
    tlsOptions?: tls.ConnectionOptions;
};
export type TcpConnectionPoolTransportDefaults = {
    protocol?: TcpConnectionPoolProtocol;
    tlsOptions?: tls.ConnectionOptions;
};
export type TcpConnectionPoolOptions = {
    idleTimeoutMs?: number;
    queryTimeoutMs?: number;
    connectTimeoutMs?: number;
    maxQueriesPerConnection?: number;
};
export declare class TcpConnectionPool extends AClient {
    private readonly _connections;
    private readonly _options;
    private _closed;
    constructor(options?: TcpConnectionPoolOptions);
    send(target: TcpConnectionPoolTarget, message: Buffer): Promise<Buffer>;
    asResolverTransport(defaults?: TcpConnectionPoolTransportDefaults): RecursiveResolverTransport;
    close(): void;
    size(): number;
    private _acquire;
    private static _keyFor;
}
