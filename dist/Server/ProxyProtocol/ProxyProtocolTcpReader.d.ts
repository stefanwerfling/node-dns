import { Buffer } from 'buffer';
import tcp from 'net';
export type ProxyProtocolBytesNeeded = (data: Buffer) => number | null;
export type ProxyProtocolSocketReadResult = {
    header: Buffer;
    remainder: Buffer;
};
export declare class ProxyProtocolTcpReader {
    static readHeader(socket: tcp.Socket, bytesNeeded: ProxyProtocolBytesNeeded): Promise<ProxyProtocolSocketReadResult>;
}
