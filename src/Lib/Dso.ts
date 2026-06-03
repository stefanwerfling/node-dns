import {Buffer} from 'buffer';
import {PacketHeader} from '../Packet/PacketHeader.js';
import {PacketName} from '../Packet/PacketName.js';
import {PacketOpcode} from '../Packet/PacketOpcode.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {BufferReader} from './BufferReader.js';
import {BufferWriter} from './BufferWriter.js';

/**
 * DSO TLV type codes. RFC 8490 reserves the low half of the space for
 * the framework-level TLVs (KEEPALIVE / RETRY_DELAY / ENCRYPTION_PADDING),
 * RFC 8765 the next quadrant for DNS Push.
 *
 * @docs https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-dso-type-codes
 */
export enum DsoTlvType {

    /**
     * RFC 8490 §7.1. Carries `INACTIVITY` and `KEEPALIVE` 32-bit
     * milliseconds. Sent first on any DSO session that wants a
     * non-default keepalive window.
     */
    KEEPALIVE = 0x0000,

    /**
     * RFC 8490 §7.2. Server tells the client how long to wait before
     * reconnecting after a forced close. 32-bit milliseconds.
     */
    RETRY_DELAY = 0x0001,

    /**
     * RFC 8490 §7.3. Opaque bytes that pad a message to a desired size
     * — counter-traffic-analysis hint, optional.
     */
    ENCRYPTION_PADDING = 0x0002,

    /**
     * RFC 8765 §6.1. Client → server subscription request. Data:
     * uncompressed wire-format NAME, 16-bit TYPE, 16-bit CLASS.
     */
    SUBSCRIBE = 0x0040,

    /**
     * RFC 8765 §6.3. Server → client unsolicited update. Data: zero
     * or more resource records in wire format.
     */
    PUSH = 0x0041,

    /**
     * RFC 8765 §6.4. Client → server unsubscribe. Data: 2-byte
     * message ID of the original SUBSCRIBE.
     */
    UNSUBSCRIBE = 0x0042,

    /**
     * RFC 8765 §6.5. Client → server "is this record still valid?".
     * Data: NAME + TYPE (16) + CLASS (16) + RDLENGTH (16) + RDATA.
     * No TTL — RECONFIRM is a query, not a known good record.
     */
    RECONFIRM = 0x0043
}

/**
 * Default DSO message ID for unilateral server-initiated messages
 * (PUSH that doesn't expect a response). RFC 8490 §5.4: "Unsolicited
 * DSO Messages MUST use a Message ID of zero (0)".
 */
export const DSO_UNILATERAL_MESSAGE_ID: number = 0;

/**
 * Common shape for every DSO TLV. Each implementation owns its
 * type-specific data and knows how to serialize itself into the body
 * stream — `encode()` writes the full TLV (type + length + data), so
 * callers can just iterate and let each TLV emit its bytes.
 */
export interface DsoTlv {

    /**
     * 16-bit TLV type. Stable across the wire — see `DsoTlvType`.
     */
    readonly type: number;

    /**
     * Append the encoded TLV (`type` + `length` + `data`) to `writer`.
     */
    encode(writer: BufferWriter): void;

}

/* ---------------- KEEPALIVE -------------------------------------- */

export class KeepaliveTlv implements DsoTlv {

    public readonly type: number = DsoTlvType.KEEPALIVE;
    public inactivityMs: number;
    public keepaliveMs: number;

    public constructor(inactivityMs: number, keepaliveMs: number) {
        this.inactivityMs = inactivityMs;
        this.keepaliveMs = keepaliveMs;
    }

    public encode(writer: BufferWriter): void {
        writer.write(this.type, 16);
        writer.write(8, 16);
        writer.write(this.inactivityMs >>> 0, 32);
        writer.write(this.keepaliveMs >>> 0, 32);
    }

    public static decode(reader: BufferReader, length: number): KeepaliveTlv {
        if (length !== 8) {
            throw new Error(`Dso.KEEPALIVE: expected 8 bytes, got ${length}`);
        }

        const inactivity = reader.read(32);
        const keepalive = reader.read(32);
        return new KeepaliveTlv(inactivity, keepalive);
    }

}

/* ---------------- RETRY_DELAY ------------------------------------ */

export class RetryDelayTlv implements DsoTlv {

    public readonly type: number = DsoTlvType.RETRY_DELAY;
    public retryDelayMs: number;

    public constructor(retryDelayMs: number) {
        this.retryDelayMs = retryDelayMs;
    }

    public encode(writer: BufferWriter): void {
        writer.write(this.type, 16);
        writer.write(4, 16);
        writer.write(this.retryDelayMs >>> 0, 32);
    }

    public static decode(reader: BufferReader, length: number): RetryDelayTlv {
        if (length !== 4) {
            throw new Error(`Dso.RETRY_DELAY: expected 4 bytes, got ${length}`);
        }

        return new RetryDelayTlv(reader.read(32));
    }

}

/* ---------------- ENCRYPTION_PADDING ----------------------------- */

export class EncryptionPaddingTlv implements DsoTlv {

    public readonly type: number = DsoTlvType.ENCRYPTION_PADDING;
    public padding: Buffer;

    public constructor(padding: Buffer) {
        this.padding = padding;
    }

    public encode(writer: BufferWriter): void {
        writer.write(this.type, 16);
        writer.write(this.padding.length, 16);
        writer.writeBuffer(this.padding);
    }

    public static decode(reader: BufferReader, length: number): EncryptionPaddingTlv {
        const bytes: number[] = [];
        for (let i = 0; i < length; i++) {
            bytes.push(reader.read(8));
        }
        return new EncryptionPaddingTlv(Buffer.from(bytes));
    }

}

/* ---------------- SUBSCRIBE -------------------------------------- */

export class SubscribeTlv implements DsoTlv {

    public readonly type: number = DsoTlvType.SUBSCRIBE;
    public name: string;
    public qtype: number;
    public qclass: number;

    public constructor(name: string, qtype: number, qclass: number) {
        this.name = name;
        this.qtype = qtype;
        this.qclass = qclass;
    }

    public encode(writer: BufferWriter): void {
        // Build the data with a fresh writer so name compression can't
        // leak across the TLV boundary (RFC 8490 §4 forbids it).
        const data = new BufferWriter();
        PacketName.encode(this.name, data);
        data.write(this.qtype, 16);
        data.write(this.qclass, 16);
        const buf = data.toBuffer();

        writer.write(this.type, 16);
        writer.write(buf.length, 16);
        writer.writeBuffer(buf);
    }

    public static decode(reader: BufferReader, length: number): SubscribeTlv {
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

/* ---------------- PUSH ------------------------------------------- */

export class PushTlv implements DsoTlv {

    public readonly type: number = DsoTlvType.PUSH;
    public records: PacketResource[];

    public constructor(records: PacketResource[] = []) {
        this.records = records;
    }

    public encode(writer: BufferWriter): void {
        // One fresh writer per record — RFC 8490 §4 bans inter-TLV
        // compression and the safest interpretation is to suppress
        // any cross-record compression inside a TLV too (a strict
        // verifier would reject pointers that escape a record). For
        // PUSH this matters most when multiple records share a
        // suffix.
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

    public static decode(reader: BufferReader, length: number): PushTlv {
        const records: PacketResource[] = [];
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

/* ---------------- UNSUBSCRIBE ------------------------------------ */

export class UnsubscribeTlv implements DsoTlv {

    public readonly type: number = DsoTlvType.UNSUBSCRIBE;
    public originalMessageId: number;

    public constructor(originalMessageId: number) {
        this.originalMessageId = originalMessageId;
    }

    public encode(writer: BufferWriter): void {
        writer.write(this.type, 16);
        writer.write(2, 16);
        writer.write(this.originalMessageId & 0xffff, 16);
    }

    public static decode(reader: BufferReader, length: number): UnsubscribeTlv {
        if (length !== 2) {
            throw new Error(`Dso.UNSUBSCRIBE: expected 2 bytes, got ${length}`);
        }

        return new UnsubscribeTlv(reader.read(16));
    }

}

/* ---------------- RECONFIRM -------------------------------------- */

export class ReconfirmTlv implements DsoTlv {

    public readonly type: number = DsoTlvType.RECONFIRM;
    public name: string;
    public qtype: number;
    public qclass: number;
    public rdata: Buffer;

    public constructor(name: string, qtype: number, qclass: number, rdata: Buffer) {
        this.name = name;
        this.qtype = qtype;
        this.qclass = qclass;
        this.rdata = rdata;
    }

    public encode(writer: BufferWriter): void {
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

    public static decode(reader: BufferReader, length: number): ReconfirmTlv {
        const startBits = reader.getOffset();
        const name = PacketName.decode(reader);
        const qtype = reader.read(16);
        const qclass = reader.read(16);
        const rdlen = reader.read(16);

        const bytes: number[] = [];
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

/* ---------------- Unknown TLV ------------------------------------ */

/**
 * Catch-all for TLV types this codebase doesn't recognise. RFC 8490 §5
 * tells us to ignore unknown additional TLVs (rather than tearing down
 * the session) — keeping them as opaque blobs makes that possible while
 * still supporting round-trip.
 */
export class UnknownDsoTlv implements DsoTlv {

    public readonly type: number;
    public data: Buffer;

    public constructor(type: number, data: Buffer) {
        this.type = type;
        this.data = data;
    }

    public encode(writer: BufferWriter): void {
        writer.write(this.type, 16);
        writer.write(this.data.length, 16);
        writer.writeBuffer(this.data);
    }

    public static decode(reader: BufferReader, type: number, length: number): UnknownDsoTlv {
        const bytes: number[] = [];
        for (let i = 0; i < length; i++) {
            bytes.push(reader.read(8));
        }
        return new UnknownDsoTlv(type, Buffer.from(bytes));
    }

}

/* ---------------- DsoMessage ------------------------------------- */

/**
 * A complete DSO message: standard 12-byte DNS header (opcode = 6) plus
 * the TLV stream. RFC 8490 §6 stipulates that all four section counts
 * are zero — the message body lives entirely in the TLVs.
 *
 * Naming: the first TLV in a request is the **primary TLV** and tells
 * the receiver what the message is about. Subsequent TLVs are
 * **additional TLVs** (e.g. encryption padding). On a response, the
 * primary TLV may be absent — the response is just an acknowledgement
 * of the request's primary TLV identified by the matching message ID.
 */
export class DsoMessage {

    public header: PacketHeader;
    public tlvs: DsoTlv[];

    public constructor(header?: PacketHeader, tlvs: DsoTlv[] = []) {
        this.header = header ?? new PacketHeader();
        this.header.opcode = PacketOpcode.DSO;
        this.tlvs = tlvs;
    }

    /**
     * Convenience factory for the common request shape: client →
     * server, opcode = 6, all counts zero, single primary TLV.
     */
    public static request(messageId: number, primaryTlv: DsoTlv, ...additional: DsoTlv[]): DsoMessage {
        const header = new PacketHeader();
        header.id = messageId & 0xffff;
        header.qr = 0;
        header.opcode = PacketOpcode.DSO;
        return new DsoMessage(header, [primaryTlv, ...additional]);
    }

    /**
     * Convenience factory for unilateral server → client messages
     * (PUSH being the canonical case). Message ID is 0 per RFC 8490 §5.4.
     */
    public static unilateral(primaryTlv: DsoTlv, ...additional: DsoTlv[]): DsoMessage {
        const header = new PacketHeader();
        header.id = DSO_UNILATERAL_MESSAGE_ID;
        header.qr = 1;
        header.opcode = PacketOpcode.DSO;
        return new DsoMessage(header, [primaryTlv, ...additional]);
    }

    /**
     * Convenience factory for response shape: same message ID as the
     * request, QR=1, opcode=6, optional rcode, no TLVs by default.
     * RFC 8490 §5.5: responses to DSO requests SHOULD echo the
     * received TLVs only when meaningful; the simple ACK is just the
     * header.
     */
    public static response(messageId: number, rcode: number = 0, tlvs: DsoTlv[] = []): DsoMessage {
        const header = new PacketHeader();
        header.id = messageId & 0xffff;
        header.qr = 1;
        header.opcode = PacketOpcode.DSO;
        header.rcode = rcode;
        return new DsoMessage(header, tlvs);
    }

    /**
     * Encode the full message (header + TLVs) into a Buffer.
     */
    public toBuffer(): Buffer {
        // Force section counts to zero per RFC 8490 §6.
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

    /**
     * Decode a message that's been received over the wire.
     *
     * The 12-byte header is parsed first; TLVs are then drained from
     * the body. Unknown types become `UnknownDsoTlv` rather than
     * being silently dropped — RFC 8490 §5.1.2 says additional TLVs
     * may be silently ignored, but keeping them round-trippable means
     * forwarders / proxies don't lose information.
     */
    public static parse(buffer: Buffer): DsoMessage {
        if (buffer.length < 12) {
            throw new Error(`DsoMessage.parse: truncated header (${buffer.length} bytes)`);
        }

        const reader = new BufferReader(buffer);
        const header = PacketHeader.parse(reader);

        if (header.opcode !== PacketOpcode.DSO) {
            throw new Error(`DsoMessage.parse: opcode ${header.opcode} is not DSO (${PacketOpcode.DSO})`);
        }

        // RFC 8490 §6 — counts must be zero. Be tolerant on parse but
        // signal the caller via the parsed counts (which would be on
        // the header even if non-zero); we don't reject the message,
        // we just don't try to walk question/answer sections.
        const tlvs: DsoTlv[] = [];
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

    /**
     * Dispatch the TLV type to the right decoder.
     *
     * @param {BufferReader} reader
     * @param {number} type
     * @param {number} length
     * @return {DsoTlv}
     * @protected
     */
    protected static _decodeTlv(reader: BufferReader, type: number, length: number): DsoTlv {
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

    /**
     * The first (primary) TLV in the message, or `undefined` when the
     * message is a bare response with no body. Convenience accessor —
     * `message.tlvs[0]` works just as well.
     */
    public get primary(): DsoTlv | undefined {
        return this.tlvs[0];
    }

}