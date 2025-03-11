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
};
