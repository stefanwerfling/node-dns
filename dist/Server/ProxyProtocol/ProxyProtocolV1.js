import { Buffer } from 'buffer';
import { ProxyProtocolCommand, ProxyProtocolFamily, ProxyProtocolTransport } from './ProxyProtocolInfo.js';
export class ProxyProtocolV1 {
    static SIGNATURE = Buffer.from('PROXY ', 'ascii');
    static MAX_HEADER_LENGTH = 107;
    static detect(data) {
        if (data.length < ProxyProtocolV1.SIGNATURE.length) {
            return false;
        }
        return data.subarray(0, ProxyProtocolV1.SIGNATURE.length).equals(ProxyProtocolV1.SIGNATURE);
    }
    static bytesNeeded(data) {
        if (data.length < ProxyProtocolV1.SIGNATURE.length) {
            return null;
        }
        if (!ProxyProtocolV1.detect(data)) {
            throw new Error('PROXY v1: invalid signature');
        }
        const limit = Math.min(data.length, ProxyProtocolV1.MAX_HEADER_LENGTH);
        for (let i = 0; i < limit - 1; i++) {
            if (data[i] === 0x0D && data[i + 1] === 0x0A) {
                return i + 2;
            }
        }
        if (data.length >= ProxyProtocolV1.MAX_HEADER_LENGTH) {
            throw new Error('PROXY v1: CRLF terminator not found within max header length');
        }
        return null;
    }
    static parse(data) {
        if (!ProxyProtocolV1.detect(data)) {
            throw new Error('PROXY v1: invalid signature');
        }
        const searchLimit = Math.min(data.length, ProxyProtocolV1.MAX_HEADER_LENGTH);
        let crlfAt = -1;
        for (let i = 0; i < searchLimit - 1; i++) {
            if (data[i] === 0x0D && data[i + 1] === 0x0A) {
                crlfAt = i;
                break;
            }
        }
        if (crlfAt === -1) {
            throw new Error('PROXY v1: CRLF terminator not found');
        }
        const line = data.subarray(0, crlfAt).toString('ascii');
        const rest = data.subarray(crlfAt + 2);
        const parts = line.split(' ');
        const proto = parts[1];
        if (proto === 'UNKNOWN') {
            return {
                info: {
                    version: 1,
                    command: ProxyProtocolCommand.PROXY,
                    family: ProxyProtocolFamily.UNSPEC,
                    transport: ProxyProtocolTransport.UNSPEC
                },
                rest: rest
            };
        }
        if (parts.length !== 6) {
            throw new Error('PROXY v1: malformed header line');
        }
        let family;
        if (proto === 'TCP4') {
            family = ProxyProtocolFamily.INET;
        }
        else if (proto === 'TCP6') {
            family = ProxyProtocolFamily.INET6;
        }
        else {
            throw new Error(`PROXY v1: unsupported protocol ${proto}`);
        }
        const srcPort = Number.parseInt(parts[4], 10);
        const dstPort = Number.parseInt(parts[5], 10);
        if (!Number.isInteger(srcPort) || srcPort < 0 || srcPort > 0xFFFF) {
            throw new Error('PROXY v1: invalid source port');
        }
        if (!Number.isInteger(dstPort) || dstPort < 0 || dstPort > 0xFFFF) {
            throw new Error('PROXY v1: invalid destination port');
        }
        const source = {
            address: parts[2],
            port: srcPort
        };
        const destination = {
            address: parts[3],
            port: dstPort
        };
        return {
            info: {
                version: 1,
                command: ProxyProtocolCommand.PROXY,
                family: family,
                transport: ProxyProtocolTransport.STREAM,
                source: source,
                destination: destination
            },
            rest: rest
        };
    }
    async process(data, client) {
        const parsed = ProxyProtocolV1.parse(data);
        if (!parsed.info.source) {
            return {
                data: parsed.rest
            };
        }
        const overridden = {
            address: parsed.info.source.address,
            port: parsed.info.source.port,
            family: parsed.info.family === ProxyProtocolFamily.INET6 ? 'IPv6' : 'IPv4',
            size: parsed.rest.length
        };
        return {
            data: parsed.rest,
            client: overridden
        };
    }
}
//# sourceMappingURL=ProxyProtocolV1.js.map