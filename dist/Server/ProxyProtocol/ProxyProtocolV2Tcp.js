import { ProxyProtocolFamily } from './ProxyProtocolInfo.js';
import { ProxyProtocolTcpReader } from './ProxyProtocolTcpReader.js';
import { ProxyProtocolV2 } from './ProxyProtocolV2.js';
export class ProxyProtocolV2Tcp {
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
        const read = await ProxyProtocolTcpReader.readHeader(client, ProxyProtocolV2.bytesNeeded);
        const parsed = ProxyProtocolV2.parse(read.header);
        ProxyProtocolV2Tcp.applyClientOverride(client, parsed.info);
        return {
            client: client,
            initialBuffer: read.remainder
        };
    }
}
//# sourceMappingURL=ProxyProtocolV2Tcp.js.map