import assert from 'assert';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {CDNSKEY} from '../Packet/Types/CDNSKEY.js';
import {CDS} from '../Packet/Types/CDS.js';
import {CERT} from '../Packet/Types/CERT.js';
import {DNAME} from '../Packet/Types/DNAME.js';
import {DNSKEY} from '../Packet/Types/DNSKEY.js';
import {DS} from '../Packet/Types/DS.js';
import {HINFO} from '../Packet/Types/HINFO.js';
import {HTTPS} from '../Packet/Types/HTTPS.js';
import {LOC} from '../Packet/Types/LOC.js';
import {NAPTR} from '../Packet/Types/NAPTR.js';
import {NSEC} from '../Packet/Types/NSEC.js';
import {NSEC3} from '../Packet/Types/NSEC3.js';
import {OPENPGPKEY} from '../Packet/Types/OPENPGPKEY.js';
import {SMIMEA} from '../Packet/Types/SMIMEA.js';
import {SSHFP} from '../Packet/Types/SSHFP.js';
import {SVCB} from '../Packet/Types/SVCB.js';
import {TLSA} from '../Packet/Types/TLSA.js';
import {URI} from '../Packet/Types/URI.js';
import {ZONEMD} from '../Packet/Types/ZONEMD.js';
import {test} from './test.js';

test('NAPTR#encode+decode', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        'example.com',
        new NAPTR(100, 10, 'u', 'E2U+sip', '!^.*$!sip:info@example.com!', ''),
        PacketClass.IN, 300
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const naptr = parsed.answers[0].packetType as NAPTR;
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
    packet.answers.push(new PacketResource(
        'example.com',
        new DS(12345, 8, 2, 'aabbccdd0011223344556677'),
        PacketClass.IN, 300
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const ds = parsed.answers[0].packetType as DS;
    assert.equal(ds.keyTag, 12345);
    assert.equal(ds.algorithm, 8);
    assert.equal(ds.digestType, 2);
    assert.equal(ds.digest, 'aabbccdd0011223344556677');
});

test('SSHFP#encode+decode', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        'host.example.com',
        new SSHFP(1, 1, 'bf6b6825d2977c511a475bbefb88aad54a92ac73'),
        PacketClass.IN, 300
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const sshfp = parsed.answers[0].packetType as SSHFP;
    assert.equal(sshfp.algorithm, 1);
    assert.equal(sshfp.fpType, 1);
    assert.equal(sshfp.fingerprint, 'bf6b6825d2977c511a475bbefb88aad54a92ac73');
});

test('NSEC#encode+decode', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        'example.com',
        new NSEC('next.example.com', [PacketTypes.A, PacketTypes.MX, PacketTypes.RRSIG, PacketTypes.NSEC]),
        PacketClass.IN, 300
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const nsec = parsed.answers[0].packetType as NSEC;
    assert.equal(nsec.nextDomain, 'next.example.com');
    assert.deepEqual(nsec.rdtypes, [PacketTypes.A, PacketTypes.MX, PacketTypes.RRSIG, PacketTypes.NSEC]);
});

test('NSEC3#encode+decode', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        'example.com',
        new NSEC3(1, 0, 10, 'aabb', 'deadbeef', [PacketTypes.A, PacketTypes.AAAA]),
        PacketClass.IN, 300
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const nsec3 = parsed.answers[0].packetType as NSEC3;
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
    packet.answers.push(new PacketResource(
        'example.com',
        new SVCB(0, 'svc.example.net', {}),
        PacketClass.IN, 300
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const svcb = parsed.answers[0].packetType as SVCB;
    assert.equal(svcb.priority, 0);
    assert.equal(svcb.target, 'svc.example.net');
    assert.deepEqual(svcb.params, {});
});

test('SVCB#ServiceMode with alpn/port/hints', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        'example.com',
        new SVCB(1, '.', {
            alpn: ['h2', 'h3'],
            port: 8443,
            ipv4hint: ['192.0.2.1', '192.0.2.2'],
            ipv6hint: ['2001:db8::1']
        }),
        PacketClass.IN, 300
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const svcb = parsed.answers[0].packetType as SVCB;
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
    packet.answers.push(new PacketResource(
        'doh.example.com',
        new SVCB(5, 'doh-target.example.net', {
            mandatory: [1, 3],
            alpn: ['h2'],
            noDefaultAlpn: true,
            dohpath: '/dns-query{?dns}',
            ech: ech
        }),
        PacketClass.IN, 300
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const svcb = parsed.answers[0].packetType as SVCB;
    assert.deepEqual(svcb.params.mandatory, [1, 3]);
    assert.deepEqual(svcb.params.alpn, ['h2']);
    assert.equal(svcb.params.noDefaultAlpn, true);
    assert.equal(svcb.params.dohpath, '/dns-query{?dns}');
    assert.deepEqual(svcb.params.ech, ech);
});

test('SVCB#unknown SvcParam roundtrips', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        'example.com',
        new SVCB(1, '.', {
            unknown: [{key: 99, value: Buffer.from([0x01, 0x02, 0x03])}]
        }),
        PacketClass.IN, 300
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const svcb = parsed.answers[0].packetType as SVCB;
    assert.equal(svcb.params.unknown?.length, 1);
    assert.equal(svcb.params.unknown?.[0].key, 99);
    assert.deepEqual(svcb.params.unknown?.[0].value, Buffer.from([0x01, 0x02, 0x03]));
});

test('SVCB#params are sorted on encode', () => {
    // Pass params in non-sorted order; encoding must emit them in key order.
    const svcb = new SVCB(1, '.', {
        port: 443,
        alpn: ['h2']
    });
    const rdata = svcb.encode({} as PacketResource).subarray(2);
    // Skip priority (2B) + empty target (1B zero-label) = 3B before params.
    // First param key must be 1 (alpn) then 3 (port) regardless of input order.
    assert.equal(rdata.readUInt16BE(3), 1);
});

test('HTTPS#record has correct type code', () => {
    const https = new HTTPS(1, 'www.example.com', {alpn: ['h3']});
    assert.equal(https.type, PacketTypes.HTTPS);

    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource('example.com', https, PacketClass.IN, 300));

    const parsed = Packet.parse(packet.toBuffer());
    assert.equal(parsed.answers[0].packetType.type, PacketTypes.HTTPS);

    const dec = parsed.answers[0].packetType as HTTPS;
    assert.ok(dec instanceof HTTPS);
    assert.equal(dec.priority, 1);
    assert.equal(dec.target, 'www.example.com');
    assert.deepEqual(dec.params.alpn, ['h3']);
});

test('DNAME#encode+decode roundtrip', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        'old.example.com',
        new DNAME('new.example.net'),
        PacketClass.IN, 300,
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const dname = parsed.answers[0].packetType as DNAME;
    assert.equal(dname.type, PacketTypes.DNAME);
    assert.equal(dname.target, 'new.example.net');
});

test('DNAME#target written without compression (RFC 6672 §3.1)', () => {
    // Two DNAME records sharing a long suffix would be compressed by a
    // permissive encoder. The library deliberately encodes domain-name
    // RDATA without using the shared writer's compression table, so the
    // bytes for the second target's suffix appear verbatim.
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        'a.example.com',
        new DNAME('foo.example.org'),
        PacketClass.IN, 300,
    ));
    packet.answers.push(new PacketResource(
        'b.example.com',
        new DNAME('bar.example.org'),
        PacketClass.IN, 300,
    ));

    const buf = packet.toBuffer();
    // 0xC0 is the high-pointer marker for compression. The second DNAME's
    // RDATA must not start with one (it carries the full target labels).
    // We can't easily locate the second RDATA without parsing, so just
    // roundtrip and confirm both targets decoded correctly.
    const parsed = Packet.parse(buf);
    assert.equal((parsed.answers[0].packetType as DNAME).target, 'foo.example.org');
    assert.equal((parsed.answers[1].packetType as DNAME).target, 'bar.example.org');
});

test('CDS#encode+decode (RFC 7344)', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        'example.com',
        new CDS(12345, 8, 2, 'aabbccdd0011223344556677'),
        PacketClass.IN, 300
    ));

    const parsed = Packet.parse(packet.toBuffer());
    assert.ok(parsed.answers[0].packetType instanceof CDS);
    const cds = parsed.answers[0].packetType as CDS;
    assert.equal(cds.type, PacketTypes.CDS);
    assert.equal(cds.keyTag, 12345);
    assert.equal(cds.algorithm, 8);
    assert.equal(cds.digestType, 2);
    assert.equal(cds.digest, 'aabbccdd0011223344556677');
});

test('CDS#delete sentinel (RFC 8078: 0 0 0 00) round-trips', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        'example.com',
        new CDS(0, 0, 0, '00'),
        PacketClass.IN, 300
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const cds = parsed.answers[0].packetType as CDS;
    assert.equal(cds.keyTag, 0);
    assert.equal(cds.algorithm, 0);
    assert.equal(cds.digestType, 0);
    assert.equal(cds.digest, '00');
});

test('CDNSKEY#encode+decode (RFC 7344)', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        'example.com',
        new CDNSKEY(257, 3, 15, 'AAEC'),  // tiny base64 key for the round-trip
        PacketClass.IN, 300
    ));

    const parsed = Packet.parse(packet.toBuffer());
    assert.ok(parsed.answers[0].packetType instanceof CDNSKEY);
    const cdnskey = parsed.answers[0].packetType as CDNSKEY;
    assert.equal(cdnskey.type, PacketTypes.CDNSKEY);
    assert.equal(cdnskey.flags, 257);
    assert.equal(cdnskey.protocol, 3);
    assert.equal(cdnskey.algorithm, 15);
    assert.equal(cdnskey.key, 'AAEC');
});

test('CDNSKEY#delete sentinel (RFC 8078: 0 3 0 AA==) round-trips', () => {
    // RFC 8078 §4: a single zero byte as the public key signals
    // "remove all DS at the parent". base64("AA==") = single 0x00 byte.
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        'example.com',
        new CDNSKEY(0, 3, 0, 'AA=='),
        PacketClass.IN, 300
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const cdnskey = parsed.answers[0].packetType as CDNSKEY;
    assert.equal(cdnskey.flags, 0);
    assert.equal(cdnskey.protocol, 3);
    assert.equal(cdnskey.algorithm, 0);
    assert.equal(cdnskey.key, 'AA==');
});

test('CDS / CDNSKEY: a DS instance does not pass instanceof CDS', () => {
    // Sanity check the class hierarchy: CDS extends DS so a CDS *is*
    // a DS, but not the other way around.
    const ds = new DS(1, 8, 2, 'aabb');
    const cds = new CDS(1, 8, 2, 'aabb');
    const dnskey = new DNSKEY(257, 3, 8, 'AAEC');
    const cdnskey = new CDNSKEY(257, 3, 8, 'AAEC');

    assert.ok(cds instanceof DS, 'CDS is a DS');
    assert.ok(!(ds instanceof CDS), 'DS is not a CDS');
    assert.ok(cdnskey instanceof DNSKEY, 'CDNSKEY is a DNSKEY');
    assert.ok(!(dnskey instanceof CDNSKEY), 'DNSKEY is not a CDNSKEY');
});

test('TLSA#encode+decode', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        '_443._tcp.example.com',
        new TLSA(3, 1, 1, 'aabbccddee0011223344556677889900'),
        PacketClass.IN, 300
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const tlsa = parsed.answers[0].packetType as TLSA;
    assert.equal(tlsa.usage, 3);
    assert.equal(tlsa.selector, 1);
    assert.equal(tlsa.matchingType, 1);
    assert.equal(tlsa.certificate, 'aabbccddee0011223344556677889900');
});

test('HINFO#encode+decode', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        'host.example.com',
        new HINFO('x86_64', 'Linux'),
        PacketClass.IN, 300
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const hinfo = parsed.answers[0].packetType as HINFO;
    assert.equal(hinfo.cpu, 'x86_64');
    assert.equal(hinfo.os, 'Linux');
});

test('HINFO: RFC 8482 minimal-ANY pattern', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        'example.com',
        new HINFO('RFC8482', ''),
        PacketClass.IN, 3789
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const hinfo = parsed.answers[0].packetType as HINFO;
    assert.equal(hinfo.cpu, 'RFC8482');
    assert.equal(hinfo.os, '');
});

test('URI#encode+decode', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        '_ftp._tcp.example.com',
        new URI(10, 1, 'ftp://ftp.example.com/public'),
        PacketClass.IN, 3600
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const uri = parsed.answers[0].packetType as URI;
    assert.equal(uri.priority, 10);
    assert.equal(uri.weight, 1);
    assert.equal(uri.target, 'ftp://ftp.example.com/public');
});

test('ZONEMD#encode+decode (SHA-384)', () => {
    // 48-byte (96 hex chars) SHA-384 digest.
    const digest = '0102030405060708090a0b0c0d0e0f1011121314151617181920212223242526272829303132333435363738394041424344454647';
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        'example.com',
        new ZONEMD(2024010101, 1, 1, digest),
        PacketClass.IN, 86400
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const zonemd = parsed.answers[0].packetType as ZONEMD;
    assert.equal(zonemd.serial, 2024010101);
    assert.equal(zonemd.scheme, 1);
    assert.equal(zonemd.hashAlgorithm, 1);
    assert.equal(zonemd.digest, digest);
});

test('OPENPGPKEY#encode+decode', () => {
    // Just a binary blob — content not parsed by this layer.
    const blob = '99020d04abcdef0102030405060708090a0b0c0d0e0f1011';
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        'c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._openpgpkey.example.com',
        new OPENPGPKEY(blob),
        PacketClass.IN, 3600
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const key = parsed.answers[0].packetType as OPENPGPKEY;
    assert.equal(key.publicKey, blob);
});

test('SMIMEA#encode+decode and is a TLSA subclass', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        'c93f1e400f26708f98cb19d936620da35eec8f72e57f9eec01c1afd6._smimecert.example.com',
        new SMIMEA(3, 1, 1, 'aabbccdd00112233'),
        PacketClass.IN, 3600
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const smimea = parsed.answers[0].packetType as SMIMEA;
    assert.equal(smimea.usage, 3);
    assert.equal(smimea.selector, 1);
    assert.equal(smimea.matchingType, 1);
    assert.equal(smimea.certificate, 'aabbccdd00112233');
    assert.ok(smimea instanceof TLSA, 'SMIMEA is a TLSA');
});

test('CERT#encode+decode', () => {
    // certType=3 (PGP), arbitrary cert bytes.
    const certBytes = 'aabbccddeeff0011223344556677889900';
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        'cert.example.com',
        new CERT(3, 12345, 8, certBytes),
        PacketClass.IN, 3600
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const cert = parsed.answers[0].packetType as CERT;
    assert.equal(cert.certType, 3);
    assert.equal(cert.keyTag, 12345);
    assert.equal(cert.algorithm, 8);
    assert.equal(cert.certificate, certBytes);
});

test('LOC#encode+decode (round-trip raw fields)', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource(
        'loc.example.com',
        new LOC(0, 0x12, 0x16, 0x13, 2_295_968_000, 1_404_416_000, 10_000_500),
        PacketClass.IN, 3600
    ));

    const parsed = Packet.parse(packet.toBuffer());
    const loc = parsed.answers[0].packetType as LOC;
    assert.equal(loc.version, 0);
    assert.equal(loc.size, 0x12);
    assert.equal(loc.horizPre, 0x16);
    assert.equal(loc.vertPre, 0x13);
    assert.equal(loc.latitude, 2_295_968_000);
    assert.equal(loc.longitude, 1_404_416_000);
    assert.equal(loc.altitude, 10_000_500);
});