import { Buffer } from 'buffer';
import { IP } from '../../Packet/IP.js';
import { ProxyProtocolCommand, ProxyProtocolFamily } from './ProxyProtocolInfo.js';
export class ProxyProtocolV2 {
    static SIGNATURE = Buffer.from([
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
        0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
    ]);
    static FIXED_HEADER_LENGTH = 16;
    static INET_BLOCK_LENGTH = 12;
    static INET6_BLOCK_LENGTH = 36;
    static detect(data) {
        if (data.length < ProxyProtocolV2.SIGNATURE.length) {
            return false;
        }
        return data.subarray(0, ProxyProtocolV2.SIGNATURE.length).equals(ProxyProtocolV2.SIGNATURE);
    }
    static bytesNeeded(data) {
        if (data.length < ProxyProtocolV2.SIGNATURE.length) {
            return null;
        }
        if (!ProxyProtocolV2.detect(data)) {
            throw new Error('PROXY v2: invalid signature');
        }
        if (data.length < ProxyProtocolV2.FIXED_HEADER_LENGTH) {
            return null;
        }
        const addrLen = data.readUInt16BE(14);
        return ProxyProtocolV2.FIXED_HEADER_LENGTH + addrLen;
    }
    static parse(data) {
        if (!ProxyProtocolV2.detect(data)) {
            throw new Error('PROXY v2: invalid signature');
        }
        if (data.length < ProxyProtocolV2.FIXED_HEADER_LENGTH) {
            throw new Error('PROXY v2: header truncated');
        }
        const verCmd = data[12];
        const version = Math.floor(verCmd / 16);
        const command = verCmd % 16;
        if (version !== 2) {
            throw new Error(`PROXY v2: unexpected version ${version}`);
        }
        if (command !== ProxyProtocolCommand.LOCAL && command !== ProxyProtocolCommand.PROXY) {
            throw new Error(`PROXY v2: unknown command ${command}`);
        }
        const famTrans = data[13];
        const family = Math.floor(famTrans / 16);
        const transport = famTrans % 16;
        const addrLen = data.readUInt16BE(14);
        const totalLen = ProxyProtocolV2.FIXED_HEADER_LENGTH + addrLen;
        if (data.length < totalLen) {
            throw new Error('PROXY v2: address block truncated');
        }
        const rest = data.subarray(totalLen);
        const info = {
            version: 2,
            command: command,
            family: family,
            transport: transport
        };
        if (command === ProxyProtocolCommand.LOCAL) {
            return {
                info: info,
                rest: rest
            };
        }
        const block = data.subarray(ProxyProtocolV2.FIXED_HEADER_LENGTH, totalLen);
        if (family === ProxyProtocolFamily.INET) {
            if (block.length < ProxyProtocolV2.INET_BLOCK_LENGTH) {
                throw new Error('PROXY v2: IPv4 block truncated');
            }
            info.source = ProxyProtocolV2.readInet(block, 0);
            info.destination = ProxyProtocolV2.readInet(block, 4);
            info.source.port = block.readUInt16BE(8);
            info.destination.port = block.readUInt16BE(10);
        }
        else if (family === ProxyProtocolFamily.INET6) {
            if (block.length < ProxyProtocolV2.INET6_BLOCK_LENGTH) {
                throw new Error('PROXY v2: IPv6 block truncated');
            }
            info.source = ProxyProtocolV2.readInet6(block, 0);
            info.destination = ProxyProtocolV2.readInet6(block, 16);
            info.source.port = block.readUInt16BE(32);
            info.destination.port = block.readUInt16BE(34);
        }
        return {
            info: info,
            rest: rest
        };
    }
    static readInet(block, offset) {
        const bytes = [
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3]
        ];
        return {
            address: bytes.join('.'),
            port: 0
        };
    }
    static readInet6(block, offset) {
        const groups = [];
        for (let i = 0; i < 16; i += 2) {
            groups.push(block.readUInt16BE(offset + i));
        }
        return {
            address: IP.toIPv6(groups),
            port: 0
        };
    }
    async process(data, client) {
        const parsed = ProxyProtocolV2.parse(data);
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
//# sourceMappingURL=ProxyProtocolV2.js.map