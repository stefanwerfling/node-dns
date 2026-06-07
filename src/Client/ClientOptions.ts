import type {ClientCookieJar} from './ClientCookieJar.js';
import type {TcpConnectionPool, TcpConnectionPoolTransportDefaults} from './TcpConnectionPool.js';

export enum ClientOptionsProtocol {
    udp,
    tcp,
    tls,
    doh,
    google
}

export type ClientOptions = {
    dns: string;
    protocol?: ClientOptionsProtocol;
    port?: number;

    /**
     * TCP/TLS connection pool to route every query through. When
     * provided, the client opens no fresh socket per request — RFC
     * 7766 §6.2 connection reuse with ID-based response correlation.
     * The pool's own `tlsOptions` defaults can be supplemented per
     * client via `poolTlsOptions`.
     */
    pool?: TcpConnectionPool;

    /**
     * Per-call defaults handed to `pool.asResolverTransport()`-style
     * routing. Currently only `tlsOptions` is consulted — the client
     * already knows `protocol` from `option.protocol`.
     */
    poolDefaults?: Pick<TcpConnectionPoolTransportDefaults, 'tlsOptions'>;

    /**
     * UDPClient only. When the DNS server sets the TC (truncation) bit in
     * the UDP response header, automatically retry the same query over TCP
     * against the same nameserver so the full answer is returned.
     * Defaults to `true` (RFC 7766 §8 recommended behaviour).
     */
    tcpFallback?: boolean;

    /**
     * UDPClient only. Port to use for the TCP retry. Defaults to the UDP
     * port, which matches the usual DNS setup (both on 53).
     */
    tcpFallbackPort?: number;

    /**
     * Apply 0x20 case-randomization to the QNAME and verify the response
     * echoes back the same case (RFC 5452 §9.2). When the case-mismatch
     * check fires, the resolver throws — the response is treated as a
     * possible spoofing attempt rather than returned silently. Off by
     * default; some legacy recursors normalize case in their replies and
     * would break with `use0x20: true`.
     */
    use0x20?: boolean;

    /**
     * UDPClient only. Attach a DNS Cookie (RFC 7873) EDNS option to
     * every outgoing query and learn the upstream's server cookie from
     * each response. On BADCOOKIE (extended rcode 23) the client retries
     * the query exactly once with the freshly-issued server cookie, so
     * cookie-aware recursors stop rate-limiting the connection.
     *
     * `true` allocates a private `ClientCookieJar` for this client.
     * Passing a `ClientCookieJar` instance shares the jar across
     * multiple clients — useful when the same process talks to a fixed
     * pool of upstreams over several `UDPClient.request(...)` factories.
     * Off by default.
     */
    cookies?: boolean | ClientCookieJar;
};