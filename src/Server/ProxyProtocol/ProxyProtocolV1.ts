import {Buffer} from 'buffer';
import dgram from 'dgram';
import {ServerPreRequest, ServerPreRequestResult} from '../ServerPreRequest.js';
import {
    ProxyProtocolAddress,
    ProxyProtocolCommand,
    ProxyProtocolFamily,
    ProxyProtocolParseResult,
    ProxyProtocolTransport
} from './ProxyProtocolInfo.js';

/**
 * PROXY protocol v1 (text-based) parser and UDP pre-request processor.
 *
 * Header shape:
 *   PROXY TCP4 <srcIP> <dstIP> <srcPort> <dstPort>\r\n
 *   PROXY TCP6 <srcIP> <dstIP> <srcPort> <dstPort>\r\n
 *   PROXY UNKNOWN\r\n
 *
 * @docs https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
 */
export class ProxyProtocolV1 implements ServerPreRequest<dgram.RemoteInfo> {

    /**
     * ASCII signature at the start of every v1 header.
     */
    public static readonly SIGNATURE: Buffer = Buffer.from('PROXY ', 'ascii');

    /**
     * Maximum header length including the trailing CRLF (per spec).
     */
    public static readonly MAX_HEADER_LENGTH: number = 107;

    /**
     * Check whether the given buffer looks like a PROXY v1 header.
     * @param {Buffer} data
     * @return {boolean}
     */
    public static detect(data: Buffer): boolean {
        if (data.length < ProxyProtocolV1.SIGNATURE.length) {
            return false;
        }

        return data.subarray(0, ProxyProtocolV1.SIGNATURE.length).equals(ProxyProtocolV1.SIGNATURE);
    }

    /**
     * How many bytes are needed to parse the v1 header from this buffer.
     *
     * Returns the total header byte count (including CRLF) once enough data
     * is present, or null if more bytes are required. Throws on obvious
     * protocol errors (bad signature, header too long).
     * @param {Buffer} data
     * @return {number|null}
     */
    public static bytesNeeded(data: Buffer): number|null {
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

    /**
     * Parse a v1 header from the start of the buffer.
     * @param {Buffer} data
     * @return {ProxyProtocolParseResult}
     */
    public static parse(data: Buffer): ProxyProtocolParseResult {
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

        // parts[0] === 'PROXY' (already verified by detect)
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

        let family: ProxyProtocolFamily;

        if (proto === 'TCP4') {
            family = ProxyProtocolFamily.INET;
        } else if (proto === 'TCP6') {
            family = ProxyProtocolFamily.INET6;
        } else {
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

        const source: ProxyProtocolAddress = {
            address: parts[2],
            port: srcPort
        };

        const destination: ProxyProtocolAddress = {
            address: parts[3],
            port: dstPort
        };

        return {
            info: {
                version: 1,
                command: ProxyProtocolCommand.PROXY,
                family: family,
                // v1 only covers TCP; stream is the spec-defined default.
                transport: ProxyProtocolTransport.STREAM,
                source: source,
                destination: destination
            },
            rest: rest
        };
    }

    /**
     * Strip the PROXY v1 header from the datagram and override the rinfo
     * with the real client endpoint reported by the header.
     * @param {Buffer} data
     * @param {dgram.RemoteInfo} client
     * @return {Promise<ServerPreRequestResult<dgram.RemoteInfo>>}
     */
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    public async process(data: Buffer, client: dgram.RemoteInfo): Promise<ServerPreRequestResult<dgram.RemoteInfo>> {
        const parsed = ProxyProtocolV1.parse(data);

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