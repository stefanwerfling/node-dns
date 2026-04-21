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
};