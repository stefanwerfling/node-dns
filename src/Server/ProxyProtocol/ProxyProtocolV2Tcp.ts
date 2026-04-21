import tcp from 'net';
import {ServerPreConnection, ServerPreConnectionResult} from '../ServerPreConnection.js';
import {ProxyProtocolFamily, ProxyProtocolInfo} from './ProxyProtocolInfo.js';
import {ProxyProtocolTcpReader} from './ProxyProtocolTcpReader.js';
import {ProxyProtocolV2} from './ProxyProtocolV2.js';

/**
 * TCP connection-level PROXY protocol v2 processor.
 *
 * Reads the binary v2 header once per connection, overrides the socket's
 * `remoteAddress`/`remotePort`/`remoteFamily` with the real client endpoint
 * and feeds any pre-read excess bytes back into the DNS reader.
 */
export class ProxyProtocolV2Tcp implements ServerPreConnection<tcp.Socket> {

    /**
     * Apply the parsed source endpoint to the socket via `defineProperty`.
     * @param {tcp.Socket} socket
     * @param {ProxyProtocolInfo} info
     */
    public static applyClientOverride(socket: tcp.Socket, info: ProxyProtocolInfo): void {
        if (!info.source) {
            return;
        }

        const family = info.family === ProxyProtocolFamily.INET6 ? 'IPv6' : 'IPv4';

        Object.defineProperty(socket, 'remoteAddress', {
            value: info.source.address,
            configurable: true,
            enumerable: true
        });

        Object.defineProperty(socket, 'remotePort', {
            value: info.source.port,
            configurable: true,
            enumerable: true
        });

        Object.defineProperty(socket, 'remoteFamily', {
            value: family,
            configurable: true,
            enumerable: true
        });
    }

    /**
     * Consume a v2 PROXY header from the socket.
     * @param {tcp.Socket} client
     * @return {Promise<ServerPreConnectionResult<tcp.Socket>>}
     */
    public async process(client: tcp.Socket): Promise<ServerPreConnectionResult<tcp.Socket>> {
        const read = await ProxyProtocolTcpReader.readHeader(client, ProxyProtocolV2.bytesNeeded);
        const parsed = ProxyProtocolV2.parse(read.header);

        ProxyProtocolV2Tcp.applyClientOverride(client, parsed.info);

        return {
            client: client,
            initialBuffer: read.remainder
        };
    }

}