import { Buffer } from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {IP} from '../IP.js';
import {PacketName} from '../PacketName.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * IANA-registered SvcParamKeys (RFC 9460 Section 14.3.2 + RFC 9461).
 */
export enum SvcParamKey {
    mandatory = 0,
    alpn = 1,
    noDefaultAlpn = 2,
    port = 3,
    ipv4hint = 4,
    ech = 5,
    ipv6hint = 6,
    dohpath = 7
}

/**
 * An entry for a SvcParamKey whose value the library does not interpret.
 * Stored opaquely so unknown / future keys roundtrip cleanly.
 */
export type SvcParamUnknown = {
    key: number;
    value: Buffer;
};

/**
 * Structured SvcParams — matches the IANA keys and exposes typed fields.
 * Any key not listed here can be supplied via `unknown`.
 */
export type SvcParams = {
    /**
     * List of SvcParamKeys a client MUST support for this record.
     */
    mandatory?: number[];

    /**
     * Application-Layer Protocol Negotiation protocol IDs (e.g. ["h2","h3"]).
     */
    alpn?: string[];

    /**
     * When present, clients MUST ignore the protocol's default ALPN set.
     */
    noDefaultAlpn?: boolean;

    /**
     * Override the default port for the service.
     */
    port?: number;

    /**
     * IPv4 address hints that clients MAY use while the actual address is
     * being resolved.
     */
    ipv4hint?: string[];

    /**
     * Opaque ECH (Encrypted ClientHello) configuration list.
     */
    ech?: Buffer;

    /**
     * IPv6 address hints.
     */
    ipv6hint?: string[];

    /**
     * DoH URI template path (RFC 9461).
     */
    dohpath?: string;

    /**
     * Any other SvcParamKey values encountered during decode, or that the
     * caller wants to encode verbatim.
     */
    unknown?: SvcParamUnknown[];
};

/**
 * Internal (key, value) entry after structured params have been serialized
 * into wire-format value buffers. Used to sort by key before writing.
 */
type SvcParamEntry = {
    key: number;
    value: Buffer;
};

/**
 * SVCB — Service Binding resource record (RFC 9460).
 *
 * Wire format:
 *   SvcPriority  (uint16)
 *   TargetName   (uncompressed domain name)
 *   SvcParams    (sequence of {SvcParamKey: uint16, length: uint16, value})
 *
 * SvcPriority == 0 is AliasMode (TargetName is an alias, SvcParams MUST be
 * empty). SvcPriority > 0 is ServiceMode.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc9460
 */
export class SVCB extends PacketType {

    /**
     * SvcPriority. 0 indicates AliasMode.
     */
    public priority: number;

    /**
     * TargetName. Uncompressed per RFC 9460 §2.2. May be empty to refer to
     * the owner name of the record.
     */
    public target: string;

    /**
     * Structured SvcParams.
     */
    public params: SvcParams;

    /**
     * Constructor
     * @param {number} priority
     * @param {string} target
     * @param {SvcParams} params
     */
    public constructor(priority: number = 0, target: string = '', params: SvcParams = {}) {
        super(PacketTypes.SVCB);
        this.priority = priority;
        this.target = target;
        this.params = params;
    }

    /**
     * Serialize structured SvcParams into an array of (key, valueBytes)
     * entries, ready to sort and emit.
     * @param {SvcParams} params
     * @return {SvcParamEntry[]}
     */
    protected static buildEntries(params: SvcParams): SvcParamEntry[] {
        const entries: SvcParamEntry[] = [];

        if (params.mandatory !== undefined) {
            entries.push({
                key: SvcParamKey.mandatory,
                value: SVCB.encodeUint16List(params.mandatory)
            });
        }

        if (params.alpn !== undefined) {
            entries.push({
                key: SvcParamKey.alpn,
                value: SVCB.encodeAlpnList(params.alpn)
            });
        }

        if (params.noDefaultAlpn) {
            entries.push({
                key: SvcParamKey.noDefaultAlpn,
                value: Buffer.alloc(0)
            });
        }

        if (params.port !== undefined) {
            const portBuf = Buffer.alloc(2);
            portBuf.writeUInt16BE(params.port);
            entries.push({
                key: SvcParamKey.port,
                value: portBuf
            });
        }

        if (params.ipv4hint !== undefined) {
            entries.push({
                key: SvcParamKey.ipv4hint,
                value: SVCB.encodeIpv4Hints(params.ipv4hint)
            });
        }

        if (params.ech !== undefined) {
            entries.push({
                key: SvcParamKey.ech,
                value: params.ech
            });
        }

        if (params.ipv6hint !== undefined) {
            entries.push({
                key: SvcParamKey.ipv6hint,
                value: SVCB.encodeIpv6Hints(params.ipv6hint)
            });
        }

        if (params.dohpath !== undefined) {
            entries.push({
                key: SvcParamKey.dohpath,
                value: Buffer.from(params.dohpath, 'utf8')
            });
        }

        if (params.unknown) {
            for (const entry of params.unknown) {
                entries.push({
                    key: entry.key,
                    value: entry.value
                });
            }
        }

        return entries;
    }

    /**
     * Encode a list of uint16 values (used for `mandatory`).
     * @param {number[]} keys
     * @return {Buffer}
     */
    protected static encodeUint16List(keys: number[]): Buffer {
        const buf = Buffer.alloc(keys.length * 2);

        for (let i = 0; i < keys.length; i++) {
            buf.writeUInt16BE(keys[i], i * 2);
        }

        return buf;
    }

    /**
     * Decode a list of uint16 values from a raw value buffer.
     * @param {Buffer} buf
     * @return {number[]}
     */
    protected static decodeUint16List(buf: Buffer): number[] {
        const out: number[] = [];

        for (let i = 0; i + 2 <= buf.length; i += 2) {
            out.push(buf.readUInt16BE(i));
        }

        return out;
    }

    /**
     * Encode an ALPN list as a sequence of length-prefixed (1 byte) IDs.
     * @param {string[]} alpns
     * @return {Buffer}
     */
    protected static encodeAlpnList(alpns: string[]): Buffer {
        const parts: Buffer[] = [];

        for (const id of alpns) {
            const idBuf = Buffer.from(id, 'utf8');

            if (idBuf.length > 0xFF) {
                throw new Error(`SVCB: ALPN id too long: ${id}`);
            }

            parts.push(Buffer.from([idBuf.length]));
            parts.push(idBuf);
        }

        return Buffer.concat(parts);
    }

    /**
     * Decode an ALPN list.
     * @param {Buffer} buf
     * @return {string[]}
     */
    protected static decodeAlpnList(buf: Buffer): string[] {
        const out: string[] = [];
        let i = 0;

        while (i < buf.length) {
            const len = buf[i];
            i += 1;

            if (i + len > buf.length) {
                throw new Error('SVCB: malformed ALPN list');
            }

            out.push(buf.subarray(i, i + len).toString('utf8'));
            i += len;
        }

        return out;
    }

    /**
     * Encode IPv4 hints as a flat 4-byte-per-address buffer.
     * @param {string[]} ips
     * @return {Buffer}
     */
    protected static encodeIpv4Hints(ips: string[]): Buffer {
        const buf = Buffer.alloc(ips.length * 4);

        for (let i = 0; i < ips.length; i++) {
            const parts = ips[i].split('.');

            if (parts.length !== 4) {
                throw new Error(`SVCB: invalid IPv4 hint: ${ips[i]}`);
            }

            for (let j = 0; j < 4; j++) {
                const byte = parseInt(parts[j], 10);

                if (!Number.isInteger(byte) || byte < 0 || byte > 0xFF) {
                    throw new Error(`SVCB: invalid IPv4 hint: ${ips[i]}`);
                }

                buf.writeUInt8(byte, (i * 4) + j);
            }
        }

        return buf;
    }

    /**
     * Decode IPv4 hints.
     * @param {Buffer} buf
     * @return {string[]}
     */
    protected static decodeIpv4Hints(buf: Buffer): string[] {
        const out: string[] = [];

        for (let i = 0; i + 4 <= buf.length; i += 4) {
            out.push([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]].join('.'));
        }

        return out;
    }

    /**
     * Encode IPv6 hints as a flat 16-byte-per-address buffer.
     * @param {string[]} ips
     * @return {Buffer}
     */
    protected static encodeIpv6Hints(ips: string[]): Buffer {
        const buf = Buffer.alloc(ips.length * 16);

        for (let i = 0; i < ips.length; i++) {
            const groups = IP.fromIPv6(ips[i]);

            for (let j = 0; j < 8; j++) {
                buf.writeUInt16BE(parseInt(`${groups[j]}`, 16), (i * 16) + (j * 2));
            }
        }

        return buf;
    }

    /**
     * Decode IPv6 hints.
     * @param {Buffer} buf
     * @return {string[]}
     */
    protected static decodeIpv6Hints(buf: Buffer): string[] {
        const out: string[] = [];

        for (let i = 0; i + 16 <= buf.length; i += 16) {
            const groups: number[] = [];

            for (let j = 0; j < 8; j++) {
                groups.push(buf.readUInt16BE(i + (j * 2)));
            }

            out.push(IP.toIPv6(groups));
        }

        return out;
    }

    /**
     * Encode the priority + target + params RDATA.
     * @param {number} priority
     * @param {string} target
     * @param {SvcParams} params
     * @return {Buffer}
     */
    protected static encodeRdata(priority: number, target: string, params: SvcParams): Buffer {
        const rdataWriter = new BufferWriter();

        rdataWriter.write(priority, 16);
        PacketName.encode(target, rdataWriter);

        const entries = SVCB.buildEntries(params);
        entries.sort((a, b) => a.key - b.key);

        for (const entry of entries) {
            rdataWriter.write(entry.key, 16);
            rdataWriter.write(entry.value.length, 16);
            rdataWriter.writeBuffer(entry.value);
        }

        return rdataWriter.toBuffer();
    }

    /**
     * Read `byteCount` bytes from the reader and return them as a Buffer.
     * @param {BufferReader} reader
     * @param {number} byteCount
     * @return {Buffer}
     */
    protected static readBytes(reader: BufferReader, byteCount: number): Buffer {
        const bytes: number[] = [];

        for (let i = 0; i < byteCount; i++) {
            bytes.push(reader.read(8));
        }

        return Buffer.from(bytes);
    }

    /**
     * Decode the raw params stream into structured SvcParams.
     * @param {BufferReader} reader
     * @param {number} bytesTotal
     * @return {SvcParams}
     */
    protected static decodeParams(reader: BufferReader, bytesTotal: number): SvcParams {
        const params: SvcParams = {};
        let consumed = 0;

        while (consumed + 4 <= bytesTotal) {
            const key = reader.read(16);
            const len = reader.read(16);
            const value = SVCB.readBytes(reader, len);
            consumed += 4 + len;

            switch (key) {
                case SvcParamKey.mandatory:
                    params.mandatory = SVCB.decodeUint16List(value);
                    break;
                case SvcParamKey.alpn:
                    params.alpn = SVCB.decodeAlpnList(value);
                    break;
                case SvcParamKey.noDefaultAlpn:
                    params.noDefaultAlpn = true;
                    break;
                case SvcParamKey.port:
                    if (value.length >= 2) {
                        params.port = value.readUInt16BE(0);
                    }
                    break;
                case SvcParamKey.ipv4hint:
                    params.ipv4hint = SVCB.decodeIpv4Hints(value);
                    break;
                case SvcParamKey.ech:
                    params.ech = value;
                    break;
                case SvcParamKey.ipv6hint:
                    params.ipv6hint = SVCB.decodeIpv6Hints(value);
                    break;
                case SvcParamKey.dohpath:
                    params.dohpath = value.toString('utf8');
                    break;
                default:
                    if (!params.unknown) {
                        params.unknown = [];
                    }

                    params.unknown.push({
                        key: key,
                        value: value
                    });
            }
        }

        return params;
    }

    /**
     * Shared decode path for SVCB and its subclass HTTPS — reads the common
     * wire format and instantiates via `ctor`.
     * @param {BufferReader} reader
     * @param {number} length
     * @param {new(priority: number, target: string, params: SvcParams) => T} ctor
     * @return {T}
     */
    protected static decodeInto<T extends SVCB>(
        reader: BufferReader,
        length: number,
        ctor: new(priority: number, target: string, params: SvcParams) => T
    ): T {
        const startOffset = reader.getOffset();
        const priority = reader.read(16);
        const target = PacketName.decode(reader);
        const bytesRead = (reader.getOffset() - startOffset) / 8;
        const paramsLength = length - bytesRead;
        const params = paramsLength > 0 ? SVCB.decodeParams(reader, paramsLength) : {};

        return new ctor(priority, target, params);
    }

    /**
     * Encode SVCB packet.
     * @param {PacketResource} _resource
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     */
    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;
        const rdataBuf = SVCB.encodeRdata(this.priority, this.target, this.params);

        twriter.write(rdataBuf.length, 16);
        twriter.writeBuffer(rdataBuf);

        return twriter.toBuffer();
    }

    /**
     * Decode the Buffer into an SVCB packet.
     * @param {BufferReader} reader
     * @param {number} length
     * @return {PacketType}
     */
    public static decode(reader: BufferReader, length: number): PacketType {
        return SVCB.decodeInto(reader, length, SVCB);
    }

}