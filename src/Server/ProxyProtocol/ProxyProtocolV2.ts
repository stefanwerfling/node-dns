import {Buffer} from 'buffer';
import dgram from 'dgram';
import {IP} from '../../Packet/IP.js';
import {ServerPreRequest, ServerPreRequestResult} from '../ServerPreRequest.js';
import {
    ProxyProtocolAddress,
    ProxyProtocolCommand,
    ProxyProtocolFamily,
    ProxyProtocolInfo,
    ProxyProtocolParseResult,
    ProxyProtocolTransport
} from './ProxyProtocolInfo.js';

/**
 * PROXY protocol v2 (binary) parser and UDP pre-request processor.
 *
 * Layout:
 *   byte  0-11  fixed 12-byte signature
 *   byte    12  high nibble = version (0x2), low nibble = command (LOCAL/PROXY)
 *   byte    13  high nibble = family,         low nibble = transport
 *   byte 14-15  length of the following address + TLV block (uint16 big-endian)
 *   byte   16+  address block + optional TLVs
 *
 * Total header length = 16 + length.
 *
 * @docs https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
 */
export class ProxyProtocolV2 implements ServerPreRequest<dgram.RemoteInfo> {

    /**
     * 12-byte binary signature at the start of every v2 header.
     */
    public static readonly SIGNATURE: Buffer = Buffer.from([
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
        0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
    ]);

    /**
     * Length of the fixed part (signature + 2 control bytes + 2 length bytes).
     */
    public static readonly FIXED_HEADER_LENGTH: number = 16;

    /**
     * Number of bytes needed for an IPv4 address block (2x addr + 2x port).
     */
    public static readonly INET_BLOCK_LENGTH: number = 12;

    /**
     * Number of bytes needed for an IPv6 address block (2x addr + 2x port).
     */
    public static readonly INET6_BLOCK_LENGTH: number = 36;

    /**
     * Check whether the given buffer starts with the v2 signature.
     * @param {Buffer} data
     * @return {boolean}
     */
    public static detect(data: Buffer): boolean {
        if (data.length < ProxyProtocolV2.SIGNATURE.length) {
            return false;
        }

        return data.subarray(0, ProxyProtocolV2.SIGNATURE.length).equals(ProxyProtocolV2.SIGNATURE);
    }

    /**
     * How many bytes are needed to parse the v2 header from this buffer.
     *
     * Returns the total header byte count (including TLVs) once enough data
     * is present, or null if more bytes are required. Throws on invalid
     * signature.
     * @param {Buffer} data
     * @return {number|null}
     */
    public static bytesNeeded(data: Buffer): number|null {
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

    /**
     * Parse a v2 header from the start of the buffer.
     * @param {Buffer} data
     * @return {ProxyProtocolParseResult}
     */
    public static parse(data: Buffer): ProxyProtocolParseResult {
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
        const info: ProxyProtocolInfo = {
            version: 2,
            command: command as ProxyProtocolCommand,
            family: family as ProxyProtocolFamily,
            transport: transport as ProxyProtocolTransport
        };

        // LOCAL command: ignore address information per spec.
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
        } else if (family === ProxyProtocolFamily.INET6) {
            if (block.length < ProxyProtocolV2.INET6_BLOCK_LENGTH) {
                throw new Error('PROXY v2: IPv6 block truncated');
            }

            info.source = ProxyProtocolV2.readInet6(block, 0);
            info.destination = ProxyProtocolV2.readInet6(block, 16);
            info.source.port = block.readUInt16BE(32);
            info.destination.port = block.readUInt16BE(34);
        }

        // UNSPEC / UNIX: nothing to extract into source/destination.

        return {
            info: info,
            rest: rest
        };
    }

    /**
     * Read a 4-byte IPv4 address from block starting at offset.
     * Port is filled in by the caller.
     * @param {Buffer} block
     * @param {number} offset
     * @return {ProxyProtocolAddress}
     */
    protected static readInet(block: Buffer, offset: number): ProxyProtocolAddress {
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

    /**
     * Read a 16-byte IPv6 address from block starting at offset.
     * Port is filled in by the caller.
     * @param {Buffer} block
     * @param {number} offset
     * @return {ProxyProtocolAddress}
     */
    protected static readInet6(block: Buffer, offset: number): ProxyProtocolAddress {
        const groups: number[] = [];

        for (let i = 0; i < 16; i += 2) {
            groups.push(block.readUInt16BE(offset + i));
        }

        return {
            address: IP.toIPv6(groups),
            port: 0
        };
    }

    /**
     * Strip the PROXY v2 header from the datagram and override the rinfo
     * with the real client endpoint reported by the header.
     * @param {Buffer} data
     * @param {dgram.RemoteInfo} client
     * @return {Promise<ServerPreRequestResult<dgram.RemoteInfo>>}
     */
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    public async process(data: Buffer, client: dgram.RemoteInfo): Promise<ServerPreRequestResult<dgram.RemoteInfo>> {
        const parsed = ProxyProtocolV2.parse(data);

        if (!parsed.info.source) {
            return {
                data: parsed.rest
            };
        }

        const overridden: dgram.RemoteInfo = {
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