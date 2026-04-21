import { Buffer } from 'buffer';
export declare enum ProxyProtocolCommand {
    LOCAL = 0,
    PROXY = 1
}
export declare enum ProxyProtocolFamily {
    UNSPEC = 0,
    INET = 1,
    INET6 = 2,
    UNIX = 3
}
export declare enum ProxyProtocolTransport {
    UNSPEC = 0,
    STREAM = 1,
    DGRAM = 2
}
export type ProxyProtocolAddress = {
    address: string;
    port: number;
};
export type ProxyProtocolInfo = {
    version: 1 | 2;
    command: ProxyProtocolCommand;
    family: ProxyProtocolFamily;
    transport: ProxyProtocolTransport;
    source?: ProxyProtocolAddress;
    destination?: ProxyProtocolAddress;
};
export type ProxyProtocolParseResult = {
    info: ProxyProtocolInfo;
    rest: Buffer;
};
