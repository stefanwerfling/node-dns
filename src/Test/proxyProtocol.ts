import assert from 'assert';
import {
    ProxyProtocolCommand,
    ProxyProtocolFamily,
    ProxyProtocolTransport
} from '../Server/ProxyProtocol/ProxyProtocolInfo.js';
import {ProxyProtocolV1} from '../Server/ProxyProtocol/ProxyProtocolV1.js';
import {ProxyProtocolV2} from '../Server/ProxyProtocol/ProxyProtocolV2.js';
import {test} from './test.js';

test('ProxyProtocolV1#detect', () => {
    assert.equal(ProxyProtocolV1.detect(Buffer.from('PROXY TCP4 1.2.3.4 5.6.7.8 1000 2000\r\n')), true);
    assert.equal(ProxyProtocolV1.detect(Buffer.from('OTHER ')), false);
    assert.equal(ProxyProtocolV1.detect(Buffer.from('PRO')), false);
});

test('ProxyProtocolV1#parse TCP4', () => {
    const payload = Buffer.from([0xDE, 0xAD, 0xBE, 0xEF]);
    const header = Buffer.from('PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n');
    const data = Buffer.concat([header, payload]);

    const parsed = ProxyProtocolV1.parse(data);
    assert.equal(parsed.info.version, 1);
    assert.equal(parsed.info.command, ProxyProtocolCommand.PROXY);
    assert.equal(parsed.info.family, ProxyProtocolFamily.INET);
    assert.equal(parsed.info.transport, ProxyProtocolTransport.STREAM);
    assert.equal(parsed.info.source?.address, '192.168.0.1');
    assert.equal(parsed.info.source?.port, 56324);
    assert.equal(parsed.info.destination?.address, '192.168.0.11');
    assert.equal(parsed.info.destination?.port, 443);
    assert.deepEqual(parsed.rest, payload);
});

test('ProxyProtocolV1#parse TCP6', () => {
    const header = Buffer.from('PROXY TCP6 2001:db8::1 2001:db8::2 3000 53\r\n');
    const parsed = ProxyProtocolV1.parse(header);
    assert.equal(parsed.info.family, ProxyProtocolFamily.INET6);
    assert.equal(parsed.info.source?.address, '2001:db8::1');
    assert.equal(parsed.info.source?.port, 3000);
    assert.equal(parsed.info.destination?.address, '2001:db8::2');
    assert.equal(parsed.info.destination?.port, 53);
    assert.equal(parsed.rest.length, 0);
});

test('ProxyProtocolV1#parse UNKNOWN', () => {
    const parsed = ProxyProtocolV1.parse(Buffer.from('PROXY UNKNOWN\r\n'));
    assert.equal(parsed.info.family, ProxyProtocolFamily.UNSPEC);
    assert.equal(parsed.info.transport, ProxyProtocolTransport.UNSPEC);
    assert.equal(parsed.info.source, undefined);
});

test('ProxyProtocolV1#process overrides rinfo', async() => {
    const header = Buffer.from('PROXY TCP4 10.0.0.42 10.0.0.1 50000 53\r\n');
    const payload = Buffer.from([0x00, 0x01, 0x02]);
    const handler = new ProxyProtocolV1();
    const result = await handler.process(Buffer.concat([header, payload]), {
        address: '127.0.0.1',
        port: 12345,
        family: 'IPv4',
        size: header.length + payload.length
    });

    assert.deepEqual(result.data, payload);
    assert.equal(result.client?.address, '10.0.0.42');
    assert.equal(result.client?.port, 50000);
    assert.equal(result.client?.family, 'IPv4');
    assert.equal(result.client?.size, payload.length);
});

test('ProxyProtocolV1#parse rejects missing CRLF', () => {
    assert.throws(() => ProxyProtocolV1.parse(Buffer.from('PROXY TCP4 1.2.3.4 5.6.7.8 10 20')));
});

test('ProxyProtocolV2#detect', () => {
    assert.equal(ProxyProtocolV2.detect(ProxyProtocolV2.SIGNATURE), true);
    assert.equal(ProxyProtocolV2.detect(Buffer.from('PROXY ')), false);
    assert.equal(ProxyProtocolV2.detect(Buffer.alloc(4)), false);
});

test('ProxyProtocolV2#parse TCP4', () => {
    // Layout: verCmd=0x21 (v2+PROXY), famProto=0x11 (INET+STREAM),
    // length=12, then 4B src, 4B dst, 2B srcPort, 2B dstPort.
    const control = Buffer.from([
        0x21, 0x11, 0x00, 0x0C,
        192, 168, 0, 1,
        10, 0, 0, 1,
        0x00, 0x35,
        0xAB, 0xCD
    ]);
    const payload = Buffer.from([0xCA, 0xFE]);
    const data = Buffer.concat([ProxyProtocolV2.SIGNATURE, control, payload]);
    const parsed = ProxyProtocolV2.parse(data);

    assert.equal(parsed.info.version, 2);
    assert.equal(parsed.info.command, ProxyProtocolCommand.PROXY);
    assert.equal(parsed.info.family, ProxyProtocolFamily.INET);
    assert.equal(parsed.info.transport, ProxyProtocolTransport.STREAM);
    assert.equal(parsed.info.source?.address, '192.168.0.1');
    assert.equal(parsed.info.source?.port, 53);
    assert.equal(parsed.info.destination?.address, '10.0.0.1');
    assert.equal(parsed.info.destination?.port, 0xABCD);
    assert.deepEqual(parsed.rest, payload);
});

test('ProxyProtocolV2#parse UDP6', () => {
    // 0x22 = v2+PROXY, 0x22 = INET6+DGRAM
    const addr = Buffer.alloc(36);
    // src: 2001:db8::1
    addr.writeUInt16BE(0x2001, 0);
    addr.writeUInt16BE(0x0db8, 2);
    addr.writeUInt16BE(0x0001, 14);
    // dst: 2001:db8::2
    addr.writeUInt16BE(0x2001, 16);
    addr.writeUInt16BE(0x0db8, 18);
    addr.writeUInt16BE(0x0002, 30);
    // src port / dst port
    addr.writeUInt16BE(40000, 32);
    addr.writeUInt16BE(53, 34);

    const control = Buffer.concat([Buffer.from([0x21, 0x22, 0x00, 0x24]), addr]);
    const data = Buffer.concat([ProxyProtocolV2.SIGNATURE, control]);
    const parsed = ProxyProtocolV2.parse(data);

    assert.equal(parsed.info.family, ProxyProtocolFamily.INET6);
    assert.equal(parsed.info.transport, ProxyProtocolTransport.DGRAM);
    assert.equal(parsed.info.source?.address, '2001:db8::1');
    assert.equal(parsed.info.source?.port, 40000);
    assert.equal(parsed.info.destination?.address, '2001:db8::2');
    assert.equal(parsed.info.destination?.port, 53);
});

test('ProxyProtocolV2#parse LOCAL skips addresses', () => {
    // 0x20 = v2+LOCAL, 0x00 = UNSPEC, length 0
    const control = Buffer.from([0x20, 0x00, 0x00, 0x00]);
    const parsed = ProxyProtocolV2.parse(Buffer.concat([ProxyProtocolV2.SIGNATURE, control]));
    assert.equal(parsed.info.command, ProxyProtocolCommand.LOCAL);
    assert.equal(parsed.info.source, undefined);
    assert.equal(parsed.info.destination, undefined);
});

test('ProxyProtocolV2#parse skips TLVs beyond address block', () => {
    // signature + 0x21 + 0x12 (INET+DGRAM) + length 16 (12B addr + 4B tlv) + addr + 4B tlv
    const addrBlock = Buffer.from([
        1, 2, 3, 4,
        5, 6, 7, 8,
        0x00, 0x35,
        0x00, 0x50
    ]);
    // 4-byte junk TLV appended after the address block
    const tlv = Buffer.from([0x01, 0x00, 0x02, 0x00, 0x00]).subarray(0, 4);
    const control = Buffer.concat([Buffer.from([0x21, 0x12, 0x00, 0x10]), addrBlock, tlv]);
    const payload = Buffer.from([0xFF]);
    const data = Buffer.concat([ProxyProtocolV2.SIGNATURE, control, payload]);
    const parsed = ProxyProtocolV2.parse(data);

    assert.equal(parsed.info.transport, ProxyProtocolTransport.DGRAM);
    assert.equal(parsed.info.source?.address, '1.2.3.4');
    assert.equal(parsed.info.destination?.address, '5.6.7.8');
    assert.deepEqual(parsed.rest, payload);
});

test('ProxyProtocolV1#bytesNeeded incremental', () => {
    const full = Buffer.from('PROXY TCP4 1.2.3.4 5.6.7.8 100 200\r\nextra');
    assert.equal(ProxyProtocolV1.bytesNeeded(Buffer.from('PR')), null);
    assert.equal(ProxyProtocolV1.bytesNeeded(Buffer.from('PROXY ')), null);
    assert.equal(ProxyProtocolV1.bytesNeeded(Buffer.from('PROXY TCP4 1.2.3.4')), null);
    assert.equal(ProxyProtocolV1.bytesNeeded(full), full.indexOf('\r\n') + 2);
    assert.throws(() => ProxyProtocolV1.bytesNeeded(Buffer.from('GARB X')));
});

test('ProxyProtocolV2#bytesNeeded incremental', () => {
    // Not enough for signature yet
    assert.equal(ProxyProtocolV2.bytesNeeded(Buffer.alloc(4)), null);

    // Full signature but no length field
    assert.equal(ProxyProtocolV2.bytesNeeded(ProxyProtocolV2.SIGNATURE), null);

    // Full fixed header: signature + verCmd + famProto + length(12)
    const header = Buffer.concat([
        ProxyProtocolV2.SIGNATURE,
        Buffer.from([0x21, 0x11, 0x00, 0x0C])
    ]);
    assert.equal(ProxyProtocolV2.bytesNeeded(header), 16 + 12);

    // Invalid signature after first byte
    const bad = Buffer.from([0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0xFF]);
    assert.throws(() => ProxyProtocolV2.bytesNeeded(bad));
});

test('ProxyProtocolV2#process overrides rinfo', async() => {
    const control = Buffer.from([
        0x21, 0x12, 0x00, 0x0C,
        203, 0, 113, 7,
        198, 51, 100, 1,
        0xC3, 0x50,
        0x00, 0x35
    ]);
    const payload = Buffer.from([0xAA, 0xBB]);
    const handler = new ProxyProtocolV2();
    const result = await handler.process(
        Buffer.concat([ProxyProtocolV2.SIGNATURE, control, payload]),
        {address: '127.0.0.1', port: 12345, family: 'IPv4', size: 0}
    );

    assert.deepEqual(result.data, payload);
    assert.equal(result.client?.address, '203.0.113.7');
    assert.equal(result.client?.port, 50000);
    assert.equal(result.client?.family, 'IPv4');
});