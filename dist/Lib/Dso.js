import { Buffer } from 'buffer';
import { PacketHeader } from '../Packet/PacketHeader.js';
import { PacketName } from '../Packet/PacketName.js';
import { PacketOpcode } from '../Packet/PacketOpcode.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { BufferReader } from './BufferReader.js';
import { BufferWriter } from './BufferWriter.js';
export var DsoTlvType;
(function (DsoTlvType) {
    DsoTlvType[DsoTlvType["KEEPALIVE"] = 0] = "KEEPALIVE";
    DsoTlvType[DsoTlvType["RETRY_DELAY"] = 1] = "RETRY_DELAY";
    DsoTlvType[DsoTlvType["ENCRYPTION_PADDING"] = 2] = "ENCRYPTION_PADDING";
    DsoTlvType[DsoTlvType["SUBSCRIBE"] = 64] = "SUBSCRIBE";
    DsoTlvType[DsoTlvType["PUSH"] = 65] = "PUSH";
    DsoTlvType[DsoTlvType["UNSUBSCRIBE"] = 66] = "UNSUBSCRIBE";
    DsoTlvType[DsoTlvType["RECONFIRM"] = 67] = "RECONFIRM";
})(DsoTlvType || (DsoTlvType = {}));
export const DSO_UNILATERAL_MESSAGE_ID = 0;
export class KeepaliveTlv {
    type = DsoTlvType.KEEPALIVE;
    inactivityMs;
    keepaliveMs;
    constructor(inactivityMs, keepaliveMs) {
        this.inactivityMs = inactivityMs;
        this.keepaliveMs = keepaliveMs;
    }
    encode(writer) {
        writer.write(this.type, 16);
        writer.write(8, 16);
        writer.write(this.inactivityMs >>> 0, 32);
        writer.write(this.keepaliveMs >>> 0, 32);
    }
    static decode(reader, length) {
        if (length !== 8) {
            throw new Error(`Dso.KEEPALIVE: expected 8 bytes, got ${length}`);
        }
        const inactivity = reader.read(32);
        const keepalive = reader.read(32);
        return new KeepaliveTlv(inactivity, keepalive);
    }
}
export class RetryDelayTlv {
    type = DsoTlvType.RETRY_DELAY;
    retryDelayMs;
    constructor(retryDelayMs) {
        this.retryDelayMs = retryDelayMs;
    }
    encode(writer) {
        writer.write(this.type, 16);
        writer.write(4, 16);
        writer.write(this.retryDelayMs >>> 0, 32);
    }
    static decode(reader, length) {
        if (length !== 4) {
            throw new Error(`Dso.RETRY_DELAY: expected 4 bytes, got ${length}`);
        }
        return new RetryDelayTlv(reader.read(32));
    }
}
export class EncryptionPaddingTlv {
    type = DsoTlvType.ENCRYPTION_PADDING;
    padding;
    constructor(padding) {
        this.padding = padding;
    }
    encode(writer) {
        writer.write(this.type, 16);
        writer.write(this.padding.length, 16);
        writer.writeBuffer(this.padding);
    }
    static decode(reader, length) {
        const bytes = [];
        for (let i = 0; i < length; i++) {
            bytes.push(reader.read(8));
        }
        return new EncryptionPaddingTlv(Buffer.from(bytes));
    }
}
export class SubscribeTlv {
    type = DsoTlvType.SUBSCRIBE;
    name;
    qtype;
    qclass;
    constructor(name, qtype, qclass) {
        this.name = name;
        this.qtype = qtype;
        this.qclass = qclass;
    }
    encode(writer) {
        const data = new BufferWriter();
        PacketName.encode(this.name, data);
        data.write(this.qtype, 16);
        data.write(this.qclass, 16);
        const buf = data.toBuffer();
        writer.write(this.type, 16);
        writer.write(buf.length, 16);
        writer.writeBuffer(buf);
    }
    static decode(reader, length) {
        const startBits = reader.getOffset();
        const name = PacketName.decode(reader);
        const qtype = reader.read(16);
        const qclass = reader.read(16);
        const consumedBits = reader.getOffset() - startBits;
        if (consumedBits !== length * 8) {
            throw new Error(`Dso.SUBSCRIBE: TLV length mismatch (declared ${length}, consumed ${consumedBits / 8})`);
        }
        return new SubscribeTlv(name, qtype, qclass);
    }
}
export class PushTlv {
    type = DsoTlvType.PUSH;
    records;
    constructor(records = []) {
        this.records = records;
    }
    encode(writer) {
        const data = new BufferWriter();
        for (const r of this.records) {
            const recordBuf = PacketResource.encode(r);
            data.writeBuffer(recordBuf);
        }
        const buf = data.toBuffer();
        writer.write(this.type, 16);
        writer.write(buf.length, 16);
        writer.writeBuffer(buf);
    }
    static decode(reader, length) {
        const records = [];
        const endBits = reader.getOffset() + length * 8;
        while (reader.getOffset() < endBits) {
            records.push(PacketResource.decode(reader));
        }
        if (reader.getOffset() !== endBits) {
            throw new Error('Dso.PUSH: TLV length mismatch — last record overran the TLV');
        }
        return new PushTlv(records);
    }
}
export class UnsubscribeTlv {
    type = DsoTlvType.UNSUBSCRIBE;
    originalMessageId;
    constructor(originalMessageId) {
        this.originalMessageId = originalMessageId;
    }
    encode(writer) {
        writer.write(this.type, 16);
        writer.write(2, 16);
        writer.write(this.originalMessageId & 0xffff, 16);
    }
    static decode(reader, length) {
        if (length !== 2) {
            throw new Error(`Dso.UNSUBSCRIBE: expected 2 bytes, got ${length}`);
        }
        return new UnsubscribeTlv(reader.read(16));
    }
}
export class ReconfirmTlv {
    type = DsoTlvType.RECONFIRM;
    name;
    qtype;
    qclass;
    rdata;
    constructor(name, qtype, qclass, rdata) {
        this.name = name;
        this.qtype = qtype;
        this.qclass = qclass;
        this.rdata = rdata;
    }
    encode(writer) {
        const data = new BufferWriter();
        PacketName.encode(this.name, data);
        data.write(this.qtype, 16);
        data.write(this.qclass, 16);
        data.write(this.rdata.length, 16);
        data.writeBuffer(this.rdata);
        const buf = data.toBuffer();
        writer.write(this.type, 16);
        writer.write(buf.length, 16);
        writer.writeBuffer(buf);
    }
    static decode(reader, length) {
        const startBits = reader.getOffset();
        const name = PacketName.decode(reader);
        const qtype = reader.read(16);
        const qclass = reader.read(16);
        const rdlen = reader.read(16);
        const bytes = [];
        for (let i = 0; i < rdlen; i++) {
            bytes.push(reader.read(8));
        }
        const consumedBits = reader.getOffset() - startBits;
        if (consumedBits !== length * 8) {
            throw new Error(`Dso.RECONFIRM: TLV length mismatch (declared ${length}, consumed ${consumedBits / 8})`);
        }
        return new ReconfirmTlv(name, qtype, qclass, Buffer.from(bytes));
    }
}
export class UnknownDsoTlv {
    type;
    data;
    constructor(type, data) {
        this.type = type;
        this.data = data;
    }
    encode(writer) {
        writer.write(this.type, 16);
        writer.write(this.data.length, 16);
        writer.writeBuffer(this.data);
    }
    static decode(reader, type, length) {
        const bytes = [];
        for (let i = 0; i < length; i++) {
            bytes.push(reader.read(8));
        }
        return new UnknownDsoTlv(type, Buffer.from(bytes));
    }
}
export class DsoMessage {
    header;
    tlvs;
    constructor(header, tlvs = []) {
        this.header = header ?? new PacketHeader();
        this.header.opcode = PacketOpcode.DSO;
        this.tlvs = tlvs;
    }
    static request(messageId, primaryTlv, ...additional) {
        const header = new PacketHeader();
        header.id = messageId & 0xffff;
        header.qr = 0;
        header.opcode = PacketOpcode.DSO;
        return new DsoMessage(header, [primaryTlv, ...additional]);
    }
    static unilateral(primaryTlv, ...additional) {
        const header = new PacketHeader();
        header.id = DSO_UNILATERAL_MESSAGE_ID;
        header.qr = 1;
        header.opcode = PacketOpcode.DSO;
        return new DsoMessage(header, [primaryTlv, ...additional]);
    }
    static response(messageId, rcode = 0, tlvs = []) {
        const header = new PacketHeader();
        header.id = messageId & 0xffff;
        header.qr = 1;
        header.opcode = PacketOpcode.DSO;
        header.rcode = rcode;
        return new DsoMessage(header, tlvs);
    }
    toBuffer() {
        this.header.qdcount = 0;
        this.header.ancount = 0;
        this.header.nscount = 0;
        this.header.arcount = 0;
        const writer = new BufferWriter();
        this.header.toBuffer(writer);
        for (const tlv of this.tlvs) {
            tlv.encode(writer);
        }
        return writer.toBuffer();
    }
    static parse(buffer) {
        if (buffer.length < 12) {
            throw new Error(`DsoMessage.parse: truncated header (${buffer.length} bytes)`);
        }
        const reader = new BufferReader(buffer);
        const header = PacketHeader.parse(reader);
        if (header.opcode !== PacketOpcode.DSO) {
            throw new Error(`DsoMessage.parse: opcode ${header.opcode} is not DSO (${PacketOpcode.DSO})`);
        }
        const tlvs = [];
        const totalBits = buffer.length * 8;
        while (reader.getOffset() < totalBits) {
            if (totalBits - reader.getOffset() < 32) {
                throw new Error('DsoMessage.parse: truncated TLV header');
            }
            const type = reader.read(16);
            const length = reader.read(16);
            if (totalBits - reader.getOffset() < length * 8) {
                throw new Error(`DsoMessage.parse: truncated TLV body (type=0x${type.toString(16)}, declared length=${length})`);
            }
            tlvs.push(DsoMessage._decodeTlv(reader, type, length));
        }
        return new DsoMessage(header, tlvs);
    }
    static _decodeTlv(reader, type, length) {
        switch (type) {
            case DsoTlvType.KEEPALIVE:
                return KeepaliveTlv.decode(reader, length);
            case DsoTlvType.RETRY_DELAY:
                return RetryDelayTlv.decode(reader, length);
            case DsoTlvType.ENCRYPTION_PADDING:
                return EncryptionPaddingTlv.decode(reader, length);
            case DsoTlvType.SUBSCRIBE:
                return SubscribeTlv.decode(reader, length);
            case DsoTlvType.PUSH:
                return PushTlv.decode(reader, length);
            case DsoTlvType.UNSUBSCRIBE:
                return UnsubscribeTlv.decode(reader, length);
            case DsoTlvType.RECONFIRM:
                return ReconfirmTlv.decode(reader, length);
            default:
                return UnknownDsoTlv.decode(reader, type, length);
        }
    }
    get primary() {
        return this.tlvs[0];
    }
}
//# sourceMappingURL=Dso.js.map