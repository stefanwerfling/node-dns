import { Buffer } from 'buffer';
import dgram from 'dgram';
import { ServerPreRequest, ServerPreRequestResult } from '../ServerPreRequest.js';
import { ProxyProtocolAddress, ProxyProtocolParseResult } from './ProxyProtocolInfo.js';
export declare class ProxyProtocolV2 implements ServerPreRequest<dgram.RemoteInfo> {
    static readonly SIGNATURE: Buffer;
    static readonly FIXED_HEADER_LENGTH: number;
    static readonly INET_BLOCK_LENGTH: number;
    static readonly INET6_BLOCK_LENGTH: number;
    static detect(data: Buffer): boolean;
    static bytesNeeded(data: Buffer): number | null;
    static parse(data: Buffer): ProxyProtocolParseResult;
    protected static readInet(block: Buffer, offset: number): ProxyProtocolAddress;
    protected static readInet6(block: Buffer, offset: number): ProxyProtocolAddress;
    process(data: Buffer, client: dgram.RemoteInfo): Promise<ServerPreRequestResult<dgram.RemoteInfo>>;
}
