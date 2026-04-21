import {Buffer} from 'buffer';

/**
 * PROXY protocol command (v2 only; v1 always maps to PROXY).
 */
export enum ProxyProtocolCommand {
    LOCAL = 0,
    PROXY = 1
}

/**
 * PROXY protocol address family.
 */
export enum ProxyProtocolFamily {
    UNSPEC = 0,
    INET = 1,
    INET6 = 2,
    UNIX = 3
}

/**
 * PROXY protocol transport protocol.
 */
export enum ProxyProtocolTransport {
    UNSPEC = 0,
    STREAM = 1,
    DGRAM = 2
}

/**
 * Parsed address endpoint.
 */
export type ProxyProtocolAddress = {
    address: string;
    port: number;
};

/**
 * Parsed PROXY header metadata.
 */
export type ProxyProtocolInfo = {
    version: 1 | 2;
    command: ProxyProtocolCommand;
    family: ProxyProtocolFamily;
    transport: ProxyProtocolTransport;
    source?: ProxyProtocolAddress;
    destination?: ProxyProtocolAddress;
};

/**
 * Result of parsing a PROXY header out of a buffer.
 */
export type ProxyProtocolParseResult = {
    /**
     * Parsed header metadata.
     */
    info: ProxyProtocolInfo;

    /**
     * Remaining payload after the PROXY header has been removed.
     */
    rest: Buffer;
};