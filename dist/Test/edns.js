import assert from 'assert';
import { BufferReader } from '../Lib/BufferReader.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { EdnsChain } from '../Packet/Types/EdnsChain.js';
import { EdnsCookie } from '../Packet/Types/EdnsCookie.js';
import { EDNS, EdnsECS } from '../Packet/Types/EDNS.js';
import { EdnsExtendedError, ExtendedDnsErrorCode } from '../Packet/Types/EdnsExtendedError.js';
import { EdnsKeepalive } from '../Packet/Types/EdnsKeepalive.js';
import { EdnsNsid } from '../Packet/Types/EdnsNsid.js';
import { EdnsPadding } from '../Packet/Types/EdnsPadding.js';
import { test } from './test.js';
test('EDNS.ECS#encode', () => {
    const resource = EDNS.createResource([new EdnsECS('10.11.12.13/24')]);
    const buf = PacketResource.encode(resource);
    assert.deepEqual(buf, Buffer.from([
        0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x08, 0x00,
        0x01, 0x18, 0x00, 0x0a, 0x0b, 0x0c, 0x0d
    ]));
});
test('EDNS#decode', () => {
    const buffer = Buffer.from([
        0x00, 0x08, 0x00, 0x08, 0x00, 0x01, 0x18, 0x00, 0x0a, 0x0b, 0x0c, 0x0d
    ]);
    const reader = new BufferReader(buffer);
    const edns = EDNS.decode(reader, buffer.length);
    assert.equal(edns.rdata.length, 1);
    const ecs = edns.rdata[0];
    assert.equal(ecs.ednsCode, 8);
    assert.equal(ecs.family, 1);
    assert.equal(ecs.sourcePrefixLength, 24);
    assert.equal(ecs.scopePrefixLength, 0);
    assert.equal(ecs.ip, '10.11.12.13');
    const resource = EDNS.createResource([new EdnsECS('10.20.0.0/16')]);
    const encoded = PacketResource.encode(resource);
    const decoded = PacketResource.decode(encoded);
    const decodedEdns = decoded.packetType;
    const decodedEcs = decodedEdns.rdata[0];
    const originalEcs = resource.packetType.rdata[0];
    assert.equal(decodedEcs.ip, originalEcs.ip);
    assert.equal(decodedEcs.sourcePrefixLength, originalEcs.sourcePrefixLength);
});
test('EDNS#decode multiple', () => {
    const resource = EDNS.createResource([
        new EdnsECS('10.0.0.0/8'),
        new EdnsECS('10.9.0.0/16'),
        new EdnsECS('10.9.8.0/24'),
        new EdnsECS('10.9.8.7/32'),
    ]);
    const encoded = PacketResource.encode(resource);
    const decoded = PacketResource.decode(encoded);
    const decodedEdns = decoded.packetType;
    assert.equal(decodedEdns.rdata.length, 4);
    assert.equal(decodedEdns.rdata[0].ip, '10.0.0.0');
    assert.equal(decodedEdns.rdata[0].sourcePrefixLength, 8);
    assert.equal(decodedEdns.rdata[1].ip, '10.9.0.0');
    assert.equal(decodedEdns.rdata[2].ip, '10.9.8.0');
    assert.equal(decodedEdns.rdata[3].ip, '10.9.8.7');
    assert.equal(decodedEdns.rdata[3].sourcePrefixLength, 32);
});
test('EDNS.Padding#roundtrip', () => {
    const resource = EDNS.createResource([new EdnsPadding(32)]);
    const encoded = PacketResource.encode(resource);
    const decoded = PacketResource.decode(encoded);
    const opt = decoded.packetType.rdata[0];
    assert.equal(opt.ednsCode, 12);
    assert.equal(opt.length, 32);
});
test('EDNS.Padding#empty', () => {
    const resource = EDNS.createResource([new EdnsPadding(0)]);
    const decoded = PacketResource.decode(PacketResource.encode(resource));
    const opt = decoded.packetType.rdata[0];
    assert.equal(opt.length, 0);
});
test('EDNS.NSID#empty query', () => {
    const resource = EDNS.createResource([new EdnsNsid()]);
    const decoded = PacketResource.decode(PacketResource.encode(resource));
    const opt = decoded.packetType.rdata[0];
    assert.equal(opt.ednsCode, 3);
    assert.equal(opt.data.length, 0);
});
test('EDNS.NSID#response with identifier', () => {
    const resource = EDNS.createResource([new EdnsNsid('ns1.example.com')]);
    const decoded = PacketResource.decode(PacketResource.encode(resource));
    const opt = decoded.packetType.rdata[0];
    assert.equal(opt.data.toString('utf8'), 'ns1.example.com');
});
test('EDNS.Keepalive#client signal (no timeout)', () => {
    const resource = EDNS.createResource([new EdnsKeepalive(null)]);
    const decoded = PacketResource.decode(PacketResource.encode(resource));
    const opt = decoded.packetType.rdata[0];
    assert.equal(opt.ednsCode, 11);
    assert.equal(opt.timeout, null);
});
test('EDNS.Keepalive#server timeout', () => {
    const resource = EDNS.createResource([new EdnsKeepalive(100)]);
    const decoded = PacketResource.decode(PacketResource.encode(resource));
    const opt = decoded.packetType.rdata[0];
    assert.equal(opt.timeout, 100);
});
test('EDNS.ExtendedError#code only', () => {
    const resource = EDNS.createResource([new EdnsExtendedError(ExtendedDnsErrorCode.DNSSEC_BOGUS)]);
    const decoded = PacketResource.decode(PacketResource.encode(resource));
    const opt = decoded.packetType.rdata[0];
    assert.equal(opt.ednsCode, 15);
    assert.equal(opt.infoCode, ExtendedDnsErrorCode.DNSSEC_BOGUS);
    assert.equal(opt.extraText, '');
});
test('EDNS.ExtendedError#code with extra text', () => {
    const resource = EDNS.createResource([
        new EdnsExtendedError(ExtendedDnsErrorCode.BLOCKED, 'blocked by policy: rpz')
    ]);
    const decoded = PacketResource.decode(PacketResource.encode(resource));
    const opt = decoded.packetType.rdata[0];
    assert.equal(opt.infoCode, ExtendedDnsErrorCode.BLOCKED);
    assert.equal(opt.extraText, 'blocked by policy: rpz');
});
test('EDNS.Cookie#client-only roundtrip', () => {
    const client = Buffer.from('0102030405060708', 'hex');
    const resource = EDNS.createResource([new EdnsCookie(client)]);
    const decoded = PacketResource.decode(PacketResource.encode(resource));
    const opt = decoded.packetType.rdata[0];
    assert.equal(opt.ednsCode, 10);
    assert.deepEqual(opt.clientCookie, client);
    assert.equal(opt.serverCookie, null);
});
test('EDNS.Cookie#client+server roundtrip', () => {
    const client = Buffer.from('aabbccddeeff0011', 'hex');
    const server = Buffer.from('01000000ffffffff' + '00112233445566778899aabbccddeeff', 'hex');
    const resource = EDNS.createResource([new EdnsCookie(client, server)]);
    const decoded = PacketResource.decode(PacketResource.encode(resource));
    const opt = decoded.packetType.rdata[0];
    assert.deepEqual(opt.clientCookie, client);
    assert.deepEqual(opt.serverCookie, server);
});
test('EDNS.Cookie#constructor rejects bad lengths', () => {
    assert.throws(() => new EdnsCookie(Buffer.alloc(7)));
    assert.throws(() => new EdnsCookie(Buffer.alloc(9)));
    assert.throws(() => new EdnsCookie(Buffer.alloc(8), Buffer.alloc(7)));
    assert.throws(() => new EdnsCookie(Buffer.alloc(8), Buffer.alloc(33)));
});
test('EDNS.Cookie#generateClientCookie produces 8 random bytes', () => {
    const a = EdnsCookie.generateClientCookie();
    const b = EdnsCookie.generateClientCookie();
    assert.equal(a.length, 8);
    assert.equal(b.length, 8);
    assert.notDeepEqual(a, b);
});
test('EDNS.Cookie#computeServerCookie deterministic', () => {
    const client = Buffer.from('0102030405060708', 'hex');
    const ip = Buffer.from([192, 0, 2, 1]);
    const secret = Buffer.from('shared-server-secret');
    const a = EdnsCookie.computeServerCookie(client, ip, secret, 1700000000);
    const b = EdnsCookie.computeServerCookie(client, ip, secret, 1700000000);
    assert.equal(a.length, 24);
    assert.deepEqual(a, b);
});
test('EDNS.Cookie#verifyServerCookie accepts and rejects', () => {
    const client = Buffer.from('0102030405060708', 'hex');
    const ip = Buffer.from([192, 0, 2, 1]);
    const secret = Buffer.from('s');
    const ts = 1_700_000_000;
    const cookie = EdnsCookie.computeServerCookie(client, ip, secret, ts);
    assert.equal(EdnsCookie.verifyServerCookie(cookie, client, ip, secret), true);
    const otherClient = Buffer.from('1111111111111111', 'hex');
    assert.equal(EdnsCookie.verifyServerCookie(cookie, otherClient, ip, secret), false);
    const otherIp = Buffer.from([10, 0, 0, 1]);
    assert.equal(EdnsCookie.verifyServerCookie(cookie, client, otherIp, secret), false);
    assert.equal(EdnsCookie.verifyServerCookie(cookie, client, ip, Buffer.from('other')), false);
    const tampered = Buffer.from(cookie);
    tampered[tampered.length - 1] = (tampered[tampered.length - 1] + 1) % 256;
    assert.equal(EdnsCookie.verifyServerCookie(tampered, client, ip, secret), false);
});
test('EDNS.Cookie#verifyServerCookie enforces maxAge', () => {
    const client = Buffer.from('0102030405060708', 'hex');
    const ip = Buffer.from([192, 0, 2, 1]);
    const secret = Buffer.from('s');
    const ts = 1_700_000_000;
    const cookie = EdnsCookie.computeServerCookie(client, ip, secret, ts);
    assert.equal(EdnsCookie.verifyServerCookie(cookie, client, ip, secret, { now: ts + 60, maxAgeSeconds: 300 }), true);
    assert.equal(EdnsCookie.verifyServerCookie(cookie, client, ip, secret, { now: ts + 1000, maxAgeSeconds: 300 }), false);
});
test('EDNS#multi-option mix', () => {
    const resource = EDNS.createResource([
        new EdnsECS('192.0.2.0/24'),
        new EdnsKeepalive(null),
        new EdnsNsid('srv-x'),
        new EdnsExtendedError(ExtendedDnsErrorCode.STALE_ANSWER, 'cache hit'),
        new EdnsPadding(16)
    ]);
    const decoded = PacketResource.decode(PacketResource.encode(resource));
    const rdata = decoded.packetType.rdata;
    assert.equal(rdata.length, 5);
    assert.equal(rdata[0].ip, '192.0.2.0');
    assert.equal(rdata[1].timeout, null);
    assert.equal(rdata[2].data.toString('utf8'), 'srv-x');
    assert.equal(rdata[3].infoCode, ExtendedDnsErrorCode.STALE_ANSWER);
    assert.equal(rdata[3].extraText, 'cache hit');
    assert.equal(rdata[4].length, 16);
});
test('EDNS#createResource encodes the DO bit into the TTL field', () => {
    const off = EDNS.createResource([], 4096, false);
    assert.equal(off.ttl, 0);
    assert.equal(off.class, 4096);
    const on = EDNS.createResource([], 4096, true);
    assert.equal(on.ttl & 0x00008000, 0x00008000);
    assert.equal(on.class, 4096);
    const buf = PacketResource.encode(on);
    assert.deepEqual(buf.subarray(0, 11), Buffer.from([
        0x00,
        0x00, 0x29,
        0x10, 0x00,
        0x00, 0x00, 0x80, 0x00,
        0x00, 0x00
    ]));
});
test('EDNS.Chain#empty signals root (RFC 7901)', () => {
    const resource = EDNS.createResource([new EdnsChain()]);
    const decoded = PacketResource.decode(PacketResource.encode(resource));
    const opt = decoded.packetType.rdata[0];
    assert.equal(opt.ednsCode, 13);
    assert.equal(opt.closestTrustPoint, '');
});
test('EDNS.Chain#carries a closest trust point', () => {
    const resource = EDNS.createResource([new EdnsChain('example.com')]);
    const decoded = PacketResource.decode(PacketResource.encode(resource));
    const opt = decoded.packetType.rdata[0];
    assert.equal(opt.closestTrustPoint, 'example.com');
});
test('EDNS.Chain#round-trips deep names', () => {
    const resource = EDNS.createResource([new EdnsChain('deep.sub.zone.example.com')]);
    const decoded = PacketResource.decode(PacketResource.encode(resource));
    const opt = decoded.packetType.rdata[0];
    assert.equal(opt.closestTrustPoint, 'deep.sub.zone.example.com');
});
//# sourceMappingURL=edns.js.map