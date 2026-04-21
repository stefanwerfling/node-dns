import { Buffer } from 'buffer';
import dgram from 'dgram';
import { ServerPreRequest, ServerPreRequestResult } from '../ServerPreRequest.js';
import { ProxyProtocolParseResult } from './ProxyProtocolInfo.js';
export declare class ProxyProtocolV1 implements ServerPreRequest<dgram.RemoteInfo> {
    static readonly SIGNATURE: Buffer;
    static readonly MAX_HEADER_LENGTH: number;
    static detect(data: Buffer): boolean;
    static bytesNeeded(data: Buffer): number | null;
    static parse(data: Buffer): ProxyProtocolParseResult;
    process(data: Buffer, client: dgram.RemoteInfo): Promise<ServerPreRequestResult<dgram.RemoteInfo>>;
}
