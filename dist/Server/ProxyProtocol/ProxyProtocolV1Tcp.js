import { ProxyProtocolFamily } from './ProxyProtocolInfo.js';
import { ProxyProtocolTcpReader } from './ProxyProtocolTcpReader.js';
import { ProxyProtocolV1 } from './ProxyProtocolV1.js';
export class ProxyProtocolV1Tcp {
    static applyClientOverride(socket, info) {
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
    async process(client) {
        const read = await ProxyProtocolTcpReader.readHeader(client, ProxyProtocolV1.bytesNeeded);
        const parsed = ProxyProtocolV1.parse(read.header);
        ProxyProtocolV1Tcp.applyClientOverride(client, parsed.info);
        return {
            client: client,
            initialBuffer: read.remainder
        };
    }
}
//# sourceMappingURL=ProxyProtocolV1Tcp.js.map