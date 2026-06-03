import assert from 'assert';
import { Buffer } from 'buffer';
import { DSO_UNILATERAL_MESSAGE_ID, DsoMessage, DsoTlvType, EncryptionPaddingTlv, KeepaliveTlv, PushTlv, ReconfirmTlv, RetryDelayTlv, SubscribeTlv, UnknownDsoTlv, UnsubscribeTlv } from '../Lib/Dso.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketOpcode } from '../Packet/PacketOpcode.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { AAAA } from '../Packet/Types/AAAA.js';
import { test } from './test.js';
test('Dso.KeepaliveTlv encode/decode round-trip', () => {
    const tlv = new KeepaliveTlv(60_000, 5_000);
    const message = DsoMessage.request(0xABCD, tlv);
    const decoded = DsoMessage.parse(message.toBuffer());
    assert.equal(decoded.header.opcode, PacketOpcode.DSO);
    assert.equal(decoded.header.id, 0xABCD);
    assert.equal(decoded.tlvs.length, 1);
    assert.ok(decoded.tlvs[0] instanceof KeepaliveTlv);
    assert.equal(decoded.tlvs[0].inactivityMs, 60_000);
    assert.equal(decoded.tlvs[0].keepaliveMs, 5_000);
});
test('Dso.RetryDelayTlv encode/decode round-trip', () => {
    const tlv = new RetryDelayTlv(120_000);
    const message = DsoMessage.unilateral(tlv);
    const decoded = DsoMessage.parse(message.toBuffer());
    assert.equal(decoded.header.id, DSO_UNILATERAL_MESSAGE_ID);
    assert.equal(decoded.header.qr, 1);
    assert.ok(decoded.tlvs[0] instanceof RetryDelayTlv);
    assert.equal(decoded.tlvs[0].retryDelayMs, 120_000);
});
test('Dso.EncryptionPaddingTlv preserves arbitrary bytes', () => {
    const padding = Buffer.from([0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56]);
    const tlv = new EncryptionPaddingTlv(padding);
    const message = DsoMessage.request(1, new KeepaliveTlv(60_000, 5_000), tlv);
    const decoded = DsoMessage.parse(message.toBuffer());
    assert.equal(decoded.tlvs.length, 2);
    const pad = decoded.tlvs[1];
    assert.ok(pad instanceof EncryptionPaddingTlv);
    assert.deepStrictEqual(Array.from(pad.padding), Array.from(padding));
});
test('Dso.SubscribeTlv encodes name + qtype + qclass uncompressed', () => {
    const sub = new SubscribeTlv('host.example.com', PacketTypes.A, PacketClass.IN);
    const message = DsoMessage.request(42, sub);
    const decoded = DsoMessage.parse(message.toBuffer());
    assert.equal(decoded.header.id, 42);
    assert.equal(decoded.header.qr, 0);
    assert.equal(decoded.tlvs.length, 1);
    const got = decoded.tlvs[0];
    assert.ok(got instanceof SubscribeTlv);
    assert.equal(got.name, 'host.example.com');
    assert.equal(got.qtype, PacketTypes.A);
    assert.equal(got.qclass, PacketClass.IN);
});
test('Dso.UnsubscribeTlv carries the original SUBSCRIBE message id', () => {
    const tlv = new UnsubscribeTlv(0xABCD);
    const message = DsoMessage.request(99, tlv);
    const decoded = DsoMessage.parse(message.toBuffer());
    const got = decoded.tlvs[0];
    assert.ok(got instanceof UnsubscribeTlv);
    assert.equal(got.originalMessageId, 0xABCD);
});
test('Dso.PushTlv round-trip carries answer records', () => {
    const records = [
        new PacketResource('host.example.com', new A('192.0.2.1'), PacketClass.IN, 60),
        new PacketResource('host.example.com', new AAAA('2001:db8::1'), PacketClass.IN, 60)
    ];
    const tlv = new PushTlv(records);
    const message = DsoMessage.unilateral(tlv);
    const decoded = DsoMessage.parse(message.toBuffer());
    assert.equal(decoded.header.id, DSO_UNILATERAL_MESSAGE_ID);
    assert.equal(decoded.header.qr, 1);
    const got = decoded.tlvs[0];
    assert.ok(got instanceof PushTlv);
    assert.equal(got.records.length, 2);
    assert.equal(got.records[0].name, 'host.example.com');
    assert.equal(got.records[0].packetType.address, '192.0.2.1');
    assert.equal(got.records[1].packetType.address, '2001:db8::1');
});
test('Dso.ReconfirmTlv round-trip preserves NAME + TYPE + CLASS + RDATA', () => {
    const rdata = Buffer.from([192, 0, 2, 1]);
    const tlv = new ReconfirmTlv('host.example.com', PacketTypes.A, PacketClass.IN, rdata);
    const message = DsoMessage.request(7, tlv);
    const decoded = DsoMessage.parse(message.toBuffer());
    const got = decoded.tlvs[0];
    assert.ok(got instanceof ReconfirmTlv);
    assert.equal(got.name, 'host.example.com');
    assert.equal(got.qtype, PacketTypes.A);
    assert.equal(got.qclass, PacketClass.IN);
    assert.deepStrictEqual(Array.from(got.rdata), Array.from(rdata));
});
test('Dso message has opcode=6 in the wire header', () => {
    const tlv = new KeepaliveTlv(60_000, 5_000);
    const message = DsoMessage.request(0x1234, tlv);
    const buf = message.toBuffer();
    assert.equal(buf[2], 0x30);
});
test('Dso message zeroes all four section counts', () => {
    const tlv = new SubscribeTlv('example.com', 1, 1);
    const message = DsoMessage.request(0xFFFE, tlv);
    const buf = message.toBuffer();
    assert.equal(buf.readUInt16BE(4), 0, 'QDCOUNT');
    assert.equal(buf.readUInt16BE(6), 0, 'ANCOUNT');
    assert.equal(buf.readUInt16BE(8), 0, 'NSCOUNT');
    assert.equal(buf.readUInt16BE(10), 0, 'ARCOUNT');
});
test('Dso TLV wire format is type|length|data with 16-bit big-endian fields', () => {
    const tlv = new RetryDelayTlv(0xDEADBEEF);
    const message = DsoMessage.request(1, tlv);
    const buf = message.toBuffer();
    assert.equal(buf.readUInt16BE(12), DsoTlvType.RETRY_DELAY);
    assert.equal(buf.readUInt16BE(14), 4);
    assert.equal(buf.readUInt32BE(16), 0xDEADBEEF >>> 0);
});
test('Dso UnknownDsoTlv round-trips an unrecognised type code', () => {
    const opaque = Buffer.from([0x01, 0x02, 0x03, 0x04]);
    const tlv = new UnknownDsoTlv(0xBEEF, opaque);
    const message = DsoMessage.request(5, tlv);
    const decoded = DsoMessage.parse(message.toBuffer());
    const got = decoded.tlvs[0];
    assert.ok(got instanceof UnknownDsoTlv);
    assert.equal(got.type, 0xBEEF);
    assert.deepStrictEqual(Array.from(got.data), Array.from(opaque));
});
test('Dso parse rejects non-DSO opcode', () => {
    const buf = Buffer.alloc(12);
    buf.writeUInt16BE(0xCAFE, 0);
    assert.throws(() => DsoMessage.parse(buf), /not DSO/);
});
test('Dso parse rejects truncated TLV header', () => {
    const valid = DsoMessage.request(1, new KeepaliveTlv(0, 0)).toBuffer();
    const truncated = valid.subarray(0, valid.length - 7);
    assert.throws(() => DsoMessage.parse(truncated), /truncated TLV/);
});
test('Dso parse rejects TLV that overflows the message body', () => {
    const header = Buffer.alloc(12);
    header[2] = 0x30;
    const tlvHeader = Buffer.alloc(4);
    tlvHeader.writeUInt16BE(DsoTlvType.RETRY_DELAY, 0);
    tlvHeader.writeUInt16BE(100, 2);
    const buf = Buffer.concat([header, tlvHeader]);
    assert.throws(() => DsoMessage.parse(buf), /truncated TLV body/);
});
test('Dso message round-trips multiple TLVs in declaration order', () => {
    const message = DsoMessage.request(100, new KeepaliveTlv(60_000, 5_000), new EncryptionPaddingTlv(Buffer.from([0xFF, 0xFF])), new UnknownDsoTlv(0xCAFE, Buffer.from([0xDE, 0xAD])));
    const decoded = DsoMessage.parse(message.toBuffer());
    assert.equal(decoded.tlvs.length, 3);
    assert.ok(decoded.tlvs[0] instanceof KeepaliveTlv);
    assert.ok(decoded.tlvs[1] instanceof EncryptionPaddingTlv);
    assert.ok(decoded.tlvs[2] instanceof UnknownDsoTlv);
});
//# sourceMappingURL=dso.js.map