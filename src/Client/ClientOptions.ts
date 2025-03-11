
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
};