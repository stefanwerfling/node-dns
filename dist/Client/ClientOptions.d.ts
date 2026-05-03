import type { TcpConnectionPool, TcpConnectionPoolTransportDefaults } from './TcpConnectionPool.js';
export declare enum ClientOptionsProtocol {
    udp = 0,
    tcp = 1,
    tls = 2,
    doh = 3,
    google = 4
}
export type ClientOptions = {
    dns: string;
    protocol?: ClientOptionsProtocol;
    port?: number;
    pool?: TcpConnectionPool;
    poolDefaults?: Pick<TcpConnectionPoolTransportDefaults, 'tlsOptions'>;
    tcpFallback?: boolean;
    tcpFallbackPort?: number;
    use0x20?: boolean;
};
