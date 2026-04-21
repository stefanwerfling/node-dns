import tcp from 'net';
import { ServerPreConnection, ServerPreConnectionResult } from '../ServerPreConnection.js';
import { ProxyProtocolInfo } from './ProxyProtocolInfo.js';
export declare class ProxyProtocolV2Tcp implements ServerPreConnection<tcp.Socket> {
    static applyClientOverride(socket: tcp.Socket, info: ProxyProtocolInfo): void;
    process(client: tcp.Socket): Promise<ServerPreConnectionResult<tcp.Socket>>;
}
