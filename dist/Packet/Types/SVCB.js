import { Buffer } from 'buffer';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { IP } from '../IP.js';
import { PacketName } from '../PacketName.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export var SvcParamKey;
(function (SvcParamKey) {
    SvcParamKey[SvcParamKey["mandatory"] = 0] = "mandatory";
    SvcParamKey[SvcParamKey["alpn"] = 1] = "alpn";
    SvcParamKey[SvcParamKey["noDefaultAlpn"] = 2] = "noDefaultAlpn";
    SvcParamKey[SvcParamKey["port"] = 3] = "port";
    SvcParamKey[SvcParamKey["ipv4hint"] = 4] = "ipv4hint";
    SvcParamKey[SvcParamKey["ech"] = 5] = "ech";
    SvcParamKey[SvcParamKey["ipv6hint"] = 6] = "ipv6hint";
    SvcParamKey[SvcParamKey["dohpath"] = 7] = "dohpath";
})(SvcParamKey || (SvcParamKey = {}));
export class SVCB extends PacketType {
    priority;
    target;
    params;
    constructor(priority = 0, target = '', params = {}) {
        super(PacketTypes.SVCB);
        this.priority = priority;
        this.target = target;
        this.params = params;
    }
    static buildEntries(params) {
        const entries = [];
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
    static encodeUint16List(keys) {
        const buf = Buffer.alloc(keys.length * 2);
        for (let i = 0; i < keys.length; i++) {
            buf.writeUInt16BE(keys[i], i * 2);
        }
        return buf;
    }
    static decodeUint16List(buf) {
        const out = [];
        for (let i = 0; i + 2 <= buf.length; i += 2) {
            out.push(buf.readUInt16BE(i));
        }
        return out;
    }
    static encodeAlpnList(alpns) {
        const parts = [];
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
    static decodeAlpnList(buf) {
        const out = [];
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
    static encodeIpv4Hints(ips) {
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
    static decodeIpv4Hints(buf) {
        const out = [];
        for (let i = 0; i + 4 <= buf.length; i += 4) {
            out.push([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]].join('.'));
        }
        return out;
    }
    static encodeIpv6Hints(ips) {
        const buf = Buffer.alloc(ips.length * 16);
        for (let i = 0; i < ips.length; i++) {
            const groups = IP.fromIPv6(ips[i]);
            for (let j = 0; j < 8; j++) {
                buf.writeUInt16BE(parseInt(`${groups[j]}`, 16), (i * 16) + (j * 2));
            }
        }
        return buf;
    }
    static decodeIpv6Hints(buf) {
        const out = [];
        for (let i = 0; i + 16 <= buf.length; i += 16) {
            const groups = [];
            for (let j = 0; j < 8; j++) {
                groups.push(buf.readUInt16BE(i + (j * 2)));
            }
            out.push(IP.toIPv6(groups));
        }
        return out;
    }
    static encodeRdata(priority, target, params) {
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
    static readBytes(reader, byteCount) {
        const bytes = [];
        for (let i = 0; i < byteCount; i++) {
            bytes.push(reader.read(8));
        }
        return Buffer.from(bytes);
    }
    static decodeParams(reader, bytesTotal) {
        const params = {};
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
    static decodeInto(reader, length, ctor) {
        const startOffset = reader.getOffset();
        const priority = reader.read(16);
        const target = PacketName.decode(reader);
        const bytesRead = (reader.getOffset() - startOffset) / 8;
        const paramsLength = length - bytesRead;
        const params = paramsLength > 0 ? SVCB.decodeParams(reader, paramsLength) : {};
        return new ctor(priority, target, params);
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const rdataBuf = SVCB.encodeRdata(this.priority, this.target, this.params);
        twriter.write(rdataBuf.length, 16);
        twriter.writeBuffer(rdataBuf);
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        return SVCB.decodeInto(reader, length, SVCB);
    }
}
//# sourceMappingURL=SVCB.js.map