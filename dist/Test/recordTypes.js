import assert from 'assert';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { DNAME } from '../Packet/Types/DNAME.js';
import { DS } from '../Packet/Types/DS.js';
import { HTTPS } from '../Packet/Types/HTTPS.js';
import { NAPTR } from '../Packet/Types/NAPTR.js';
import { NSEC } from '../Packet/Types/NSEC.js';
import { NSEC3 } from '../Packet/Types/NSEC3.js';
import { SSHFP } from '../Packet/Types/SSHFP.js';
import { SVCB } from '../Packet/Types/SVCB.js';
import { TLSA } from '../Packet/Types/TLSA.js';
import { test } from './test.js';
test('NAPTR#encode+decode', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource('example.com', new NAPTR(100, 10, 'u', 'E2U+sip', '!^.*$!sip:info@example.com!', ''), PacketClass.IN, 300));
    const parsed = Packet.parse(packet.toBuffer());
    const naptr = parsed.answers[0].packetType;
    assert.equal(naptr.order, 100);
    assert.equal(naptr.preference, 10);
    assert.equal(naptr.flags, 'u');
    assert.equal(naptr.services, 'E2U+sip');
    assert.equal(naptr.regexp, '!^.*$!sip:info@example.com!');
    assert.equal(naptr.replacement, '');
});
test('DS#encode+decode', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource('example.com', new DS(12345, 8, 2, 'aabbccdd0011223344556677'), PacketClass.IN, 300));
    const parsed = Packet.parse(packet.toBuffer());
    const ds = parsed.answers[0].packetType;
    assert.equal(ds.keyTag, 12345);
    assert.equal(ds.algorithm, 8);
    assert.equal(ds.digestType, 2);
    assert.equal(ds.digest, 'aabbccdd0011223344556677');
});
test('SSHFP#encode+decode', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource('host.example.com', new SSHFP(1, 1, 'bf6b6825d2977c511a475bbefb88aad54a92ac73'), PacketClass.IN, 300));
    const parsed = Packet.parse(packet.toBuffer());
    const sshfp = parsed.answers[0].packetType;
    assert.equal(sshfp.algorithm, 1);
    assert.equal(sshfp.fpType, 1);
    assert.equal(sshfp.fingerprint, 'bf6b6825d2977c511a475bbefb88aad54a92ac73');
});
test('NSEC#encode+decode', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource('example.com', new NSEC('next.example.com', [PacketTypes.A, PacketTypes.MX, PacketTypes.RRSIG, PacketTypes.NSEC]), PacketClass.IN, 300));
    const parsed = Packet.parse(packet.toBuffer());
    const nsec = parsed.answers[0].packetType;
    assert.equal(nsec.nextDomain, 'next.example.com');
    assert.deepEqual(nsec.rdtypes, [PacketTypes.A, PacketTypes.MX, PacketTypes.RRSIG, PacketTypes.NSEC]);
});
test('NSEC3#encode+decode', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource('example.com', new NSEC3(1, 0, 10, 'aabb', 'deadbeef', [PacketTypes.A, PacketTypes.AAAA]), PacketClass.IN, 300));
    const parsed = Packet.parse(packet.toBuffer());
    const nsec3 = parsed.answers[0].packetType;
    assert.equal(nsec3.hashAlgorithm, 1);
    assert.equal(nsec3.flags, 0);
    assert.equal(nsec3.iterations, 10);
    assert.equal(nsec3.salt, 'aabb');
    assert.equal(nsec3.nextHashedOwner, 'deadbeef');
    assert.deepEqual(nsec3.rdtypes, [PacketTypes.A, PacketTypes.AAAA]);
});
test('SVCB#AliasMode roundtrip', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource('example.com', new SVCB(0, 'svc.example.net', {}), PacketClass.IN, 300));
    const parsed = Packet.parse(packet.toBuffer());
    const svcb = parsed.answers[0].packetType;
    assert.equal(svcb.priority, 0);
    assert.equal(svcb.target, 'svc.example.net');
    assert.deepEqual(svcb.params, {});
});
test('SVCB#ServiceMode with alpn/port/hints', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource('example.com', new SVCB(1, '.', {
        alpn: ['h2', 'h3'],
        port: 8443,
        ipv4hint: ['192.0.2.1', '192.0.2.2'],
        ipv6hint: ['2001:db8::1']
    }), PacketClass.IN, 300));
    const parsed = Packet.parse(packet.toBuffer());
    const svcb = parsed.answers[0].packetType;
    assert.equal(svcb.priority, 1);
    assert.equal(svcb.target, '');
    assert.deepEqual(svcb.params.alpn, ['h2', 'h3']);
    assert.equal(svcb.params.port, 8443);
    assert.deepEqual(svcb.params.ipv4hint, ['192.0.2.1', '192.0.2.2']);
    assert.deepEqual(svcb.params.ipv6hint, ['2001:db8::1']);
});
test('SVCB#mandatory + noDefaultAlpn + dohpath + ech', () => {
    const ech = Buffer.from([0xAA, 0xBB, 0xCC, 0xDD]);
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource('doh.example.com', new SVCB(5, 'doh-target.example.net', {
        mandatory: [1, 3],
        alpn: ['h2'],
        noDefaultAlpn: true,
        dohpath: '/dns-query{?dns}',
        ech: ech
    }), PacketClass.IN, 300));
    const parsed = Packet.parse(packet.toBuffer());
    const svcb = parsed.answers[0].packetType;
    assert.deepEqual(svcb.params.mandatory, [1, 3]);
    assert.deepEqual(svcb.params.alpn, ['h2']);
    assert.equal(svcb.params.noDefaultAlpn, true);
    assert.equal(svcb.params.dohpath, '/dns-query{?dns}');
    assert.deepEqual(svcb.params.ech, ech);
});
test('SVCB#unknown SvcParam roundtrips', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource('example.com', new SVCB(1, '.', {
        unknown: [{ key: 99, value: Buffer.from([0x01, 0x02, 0x03]) }]
    }), PacketClass.IN, 300));
    const parsed = Packet.parse(packet.toBuffer());
    const svcb = parsed.answers[0].packetType;
    assert.equal(svcb.params.unknown?.length, 1);
    assert.equal(svcb.params.unknown?.[0].key, 99);
    assert.deepEqual(svcb.params.unknown?.[0].value, Buffer.from([0x01, 0x02, 0x03]));
});
test('SVCB#params are sorted on encode', () => {
    const svcb = new SVCB(1, '.', {
        port: 443,
        alpn: ['h2']
    });
    const rdata = svcb.encode({}).subarray(2);
    assert.equal(rdata.readUInt16BE(3), 1);
});
test('HTTPS#record has correct type code', () => {
    const https = new HTTPS(1, 'www.example.com', { alpn: ['h3'] });
    assert.equal(https.type, PacketTypes.HTTPS);
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource('example.com', https, PacketClass.IN, 300));
    const parsed = Packet.parse(packet.toBuffer());
    assert.equal(parsed.answers[0].packetType.type, PacketTypes.HTTPS);
    const dec = parsed.answers[0].packetType;
    assert.ok(dec instanceof HTTPS);
    assert.equal(dec.priority, 1);
    assert.equal(dec.target, 'www.example.com');
    assert.deepEqual(dec.params.alpn, ['h3']);
});
test('DNAME#encode+decode roundtrip', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource('old.example.com', new DNAME('new.example.net'), PacketClass.IN, 300));
    const parsed = Packet.parse(packet.toBuffer());
    const dname = parsed.answers[0].packetType;
    assert.equal(dname.type, PacketTypes.DNAME);
    assert.equal(dname.target, 'new.example.net');
});
test('DNAME#target written without compression (RFC 6672 §3.1)', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource('a.example.com', new DNAME('foo.example.org'), PacketClass.IN, 300));
    packet.answers.push(new PacketResource('b.example.com', new DNAME('bar.example.org'), PacketClass.IN, 300));
    const buf = packet.toBuffer();
    const parsed = Packet.parse(buf);
    assert.equal(parsed.answers[0].packetType.target, 'foo.example.org');
    assert.equal(parsed.answers[1].packetType.target, 'bar.example.org');
});
test('TLSA#encode+decode', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource('_443._tcp.example.com', new TLSA(3, 1, 1, 'aabbccddee0011223344556677889900'), PacketClass.IN, 300));
    const parsed = Packet.parse(packet.toBuffer());
    const tlsa = parsed.answers[0].packetType;
    assert.equal(tlsa.usage, 3);
    assert.equal(tlsa.selector, 1);
    assert.equal(tlsa.matchingType, 1);
    assert.equal(tlsa.certificate, 'aabbccddee0011223344556677889900');
});
//# sourceMappingURL=recordTypes.js.map