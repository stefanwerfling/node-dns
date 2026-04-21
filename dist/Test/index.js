import assert from 'assert';
import http from 'http';
import tcp from 'net';
import dgram from 'dgram';
import { test } from './test.js';
import { BufferReader } from '../Lib/BufferReader.js';
import { BufferWriter } from '../Lib/BufferWriter.js';
import { IP } from '../Packet/IP.js';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketHeader } from '../Packet/PacketHeader.js';
import { PacketName } from '../Packet/PacketName.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { AAAA } from '../Packet/Types/AAAA.js';
import { CNAME } from '../Packet/Types/CNAME.js';
import { DNSKEY } from '../Packet/Types/DNSKEY.js';
import { EDNS, EdnsECS } from '../Packet/Types/EDNS.js';
import { MX } from '../Packet/Types/MX.js';
import { NS } from '../Packet/Types/NS.js';
import { PTR } from '../Packet/Types/PTR.js';
import { SOA } from '../Packet/Types/SOA.js';
import { TXT } from '../Packet/Types/TXT.js';
import { DS } from '../Packet/Types/DS.js';
import { NAPTR } from '../Packet/Types/NAPTR.js';
import { NSEC } from '../Packet/Types/NSEC.js';
import { NSEC3 } from '../Packet/Types/NSEC3.js';
import { SSHFP } from '../Packet/Types/SSHFP.js';
import { SVCB } from '../Packet/Types/SVCB.js';
import { HTTPS } from '../Packet/Types/HTTPS.js';
import { TLSA } from '../Packet/Types/TLSA.js';
import { DnsServer } from '../Server/DnsServer.js';
import { DohServer } from '../Server/DohServer.js';
import { ProxyProtocolV1 } from '../Server/ProxyProtocol/ProxyProtocolV1.js';
import { ProxyProtocolV2 } from '../Server/ProxyProtocol/ProxyProtocolV2.js';
import { ProxyProtocolV1Tcp } from '../Server/ProxyProtocol/ProxyProtocolV1Tcp.js';
import { ProxyProtocolV2Tcp } from '../Server/ProxyProtocol/ProxyProtocolV2Tcp.js';
import { ProxyProtocolCommand, ProxyProtocolFamily, ProxyProtocolTransport } from '../Server/ProxyProtocol/ProxyProtocolInfo.js';
import { TCPClient } from '../Client/TCPClient.js';
import { UDPClient } from '../Client/UDPClient.js';
const response = Buffer.from([
    0x29, 0x64, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
    0x01, 0x7a, 0x02, 0x63, 0x6e, 0x00, 0x00, 0x01,
    0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x01, 0x90, 0x00, 0x04, 0x36, 0xde,
    0x3c, 0xfc
]);
test('Name#encode', () => {
    const name = PacketName.encode('www.google.com');
    const pattern = [3, 'w', 'w', 'w', 5, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', '0'];
    assert.equal(name.length, pattern.length);
});
test('Name#compression', () => {
    const writer = new BufferWriter();
    PacketName.encode('www.example.com', writer);
    const firstLen = writer.getByteOffset();
    assert.equal(firstLen, 17);
    PacketName.encode('mail.example.com', writer);
    const secondLen = writer.getByteOffset() - firstLen;
    assert.equal(secondLen, 7);
    const buf = writer.toBuffer();
    const reader = new BufferReader(buf);
    assert.equal(PacketName.decode(reader), 'www.example.com');
    assert.equal(PacketName.decode(reader), 'mail.example.com');
});
test('Name#decode', () => {
    const reader = new BufferReader(response, 8 * 12);
    let name = PacketName.decode(reader);
    assert.equal(name, 'www.z.cn');
    reader.setOffset(8 * 26);
    name = PacketName.decode(reader);
    assert.equal(reader.getOffset(), 8 * 28);
    assert.equal(name, 'www.z.cn');
});
test('Header#encode', () => {
    const header = new PacketHeader();
    header.id = 0x2964;
    header.qr = 1;
    header.qdcount = 1;
    header.ancount = 2;
    assert.deepEqual(header.toBuffer(), Buffer.from([
        0x29, 0x64, 0x80, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00
    ]));
});
test('Header#parse', () => {
    const header = PacketHeader.parse(response);
    assert.equal(header.id, 0x2964);
    assert.equal(header.qr, 1);
    assert.equal(header.opcode, 0);
    assert.equal(header.aa, 0);
    assert.equal(header.tc, 0);
    assert.equal(header.rd, 1);
    assert.equal(header.z, 0);
    assert.equal(header.rcode, 0);
    assert.equal(header.qdcount, 1);
    assert.equal(header.ancount, 1);
    assert.equal(header.nscount, 0);
    assert.equal(header.arcount, 0);
});
test('Question#encode', () => {
    const question = new PacketQuestion('google.com', PacketTypes.A, PacketClass.IN);
    assert.deepEqual(question.toBuffer(), Buffer.from([
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
    ]));
});
test('Question#decode', () => {
    const question = new PacketQuestion('google.com', PacketTypes.A, PacketClass.IN);
    assert.deepEqual(question.toBuffer(), Buffer.from([
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
    ]));
});
test('Package#toIPv6', () => {
    assert.equal(IP.toIPv6([10756, 20034, 512, 0, 0, 0, 0, 803]), '2a04:4e42:200::323');
    assert.equal(IP.toIPv6([10755, 45248, 3, 208, 0, 0, 5057, 61441]), '2a03:b0c0:3:d0::13c1:f001');
    assert.equal(IP.toIPv6([10752, 5200, 16387, 2055, 0, 0, 0, 8206]), '2a00:1450:4003:807::200e');
    assert.equal(IP.toIPv6([9734, 18176, 12552, 0, 0, 0, 44098, 10984]), '2606:4700:3108::ac42:2ae8');
});
test('Package#fromIPv6', () => {
    assert.deepEqual(IP.fromIPv6('2a04:4e42:200::323'), [
        '2a04', '4e42', '0200', '0', '0', '0', '0', '0323'
    ]);
    assert.deepEqual(IP.fromIPv6('2a03:b0c0:3:d0::13c1:f001'), ['2a03', 'b0c0', '0003', '00d0', '0', '0', '13c1', 'f001']);
    assert.deepEqual(IP.fromIPv6('2a00:1450:4003:807::200e'), ['2a00', '1450', '4003', '0807', '0', '0', '0', '200e']);
    assert.deepEqual(IP.fromIPv6('2606:4700:3108::ac42:2ae8'), ['2606', '4700', '3108', '0', '0', '0', 'ac42', '2ae8']);
    assert.deepEqual(IP.fromIPv6('::'), ['0', '0', '0', '0', '0', '0', '0', '0']);
    assert.deepEqual(IP.fromIPv6('::2606:4700:3108'), ['0', '0', '0', '0', '0', '2606', '4700', '3108']);
    assert.deepEqual(IP.fromIPv6('606:4700:3108::'), ['0606', '4700', '3108', '0', '0', '0', '0', '0']);
});
test('Packet#parse', () => {
    const packet = Packet.parse(response);
    assert.equal(packet.questions[0].name, 'www.z.cn');
    assert.equal(packet.questions[0].type, PacketTypes.A);
    assert.equal(packet.questions[0].class, PacketClass.IN);
    assert.equal(packet.answers[0].class, PacketClass.IN);
    const aRecord = packet.answers[0].packetType;
    assert.equal(aRecord.address, '54.222.60.252');
});
test('Packet#encode', () => {
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource('lsong.org', new A('127.0.0.1'), PacketClass.IN, 300));
    packet.answers.push(new PacketResource('lsong.org', new AAAA('2001:db8::ff00:42:8329'), PacketClass.IN, 300));
    packet.answers.push(new PacketResource('lsong.org', new CNAME('sfo1.lsong.org'), PacketClass.IN, 300));
    packet.answers.push(new PacketResource('lsong.org', new PTR('sfo1.lsong.org'), PacketClass.IN, 300));
    const dnskey = new DNSKEY(256, 3, 13, 'PM8S6PI0Gf8d3HK9gHSVpW3X3zeieMEa+PLCijFuaFgiIANdUQen5xNn0/9+eo3E4VIJGU27lk6q4xXqMuQl7A==');
    packet.answers.push(new PacketResource('lsong.org', dnskey, PacketClass.IN, 300));
    packet.authorities.push(new PacketResource('lsong.org', new MX('mail.lsong.org', 5), PacketClass.IN, 300));
    packet.authorities.push(new PacketResource('lsong.org', new NS('ns1.lsong.org'), PacketClass.IN, 300));
    packet.additionals.push(new PacketResource('lsong.org', new SOA('lsong.org', 'admin@lsong.org', 2016121301, 300, 3, 10, 10), PacketClass.IN, 300));
    packet.additionals.push(new PacketResource('lsong.org', new TXT('#v=spf1 include:_spf.google.com ~all'), PacketClass.IN, 300));
    const parsed = Packet.parse(packet.toBuffer());
    assert.equal(parsed.header.qr, 1);
    assert.equal(parsed.answers.length, 5);
    assert.equal(parsed.authorities.length, 2);
    assert.equal(parsed.additionals.length, 2);
    assert.equal(parsed.answers[0].packetType.address, '127.0.0.1');
    assert.equal(parsed.answers[1].packetType.address, '2001:db8::ff00:42:8329');
    assert.equal(parsed.answers[2].packetType.domain, 'sfo1.lsong.org');
    assert.equal(parsed.answers[3].packetType.domain, 'sfo1.lsong.org');
    const parsedKey = parsed.answers[4].packetType;
    assert.equal(parsedKey.flags, 256);
    assert.equal(parsedKey.protocol, 3);
    assert.equal(parsedKey.algorithm, 13);
    assert.equal(parsedKey.zoneKey, true);
    assert.equal(parsedKey.zoneSep, false);
    assert.equal(parsedKey.key, dnskey.key);
    const mx = parsed.authorities[0].packetType;
    assert.equal(mx.exchange, 'mail.lsong.org');
    assert.equal(mx.priority, 5);
    assert.equal(parsed.authorities[1].packetType.ns, 'ns1.lsong.org');
    const soa = parsed.additionals[0].packetType;
    assert.equal(soa.primary, 'lsong.org');
    assert.equal(soa.admin, 'admin@lsong.org');
    assert.equal(soa.serial, 2016121301);
    assert.equal(parsed.additionals[1].packetType.data, '#v=spf1 include:_spf.google.com ~all');
});
test('Packet#encode array of character strings', () => {
    const dkim = [
        'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsD6Th73ZDKkFAntNZDbx',
        'Eh8VV2DSMs3re6v9/gXoT3dGcbSsuUMpfLzP5MWp4sW5cPyZxEGSiC03ZVIcCca0GRAuX9b1M0Qy25wLmPq',
        '8eT129mhwbeX50xTaXqq63A/oDM0QOPe1IeBMfPnR9tWXxvEzZKvVbmTlMY5bf+3QHLqmaEihnGlXh2LRVZ',
        'be2EMlYo18YM4LU/LkZKe06rxlq38W22TL7964tr7jmOZ+huXf2iLSg4nc4UzLwb2aOdOA+w4c87h+HW/L8',
        '0548pFguF46TKc0C0egZ+oll3Y8zySYrbkVrWFrcpnrw5qDiRVHEjxqZSubSYX+16TjNcJg9QIDAQAB'
    ];
    const packet = new Packet();
    packet.header.qr = 1;
    packet.answers.push(new PacketResource('lsong.org', new TXT(dkim), PacketClass.IN, 300));
    const parsed = Packet.parse(packet.toBuffer());
    assert.equal(parsed.answers[0].packetType.data, dkim.join(''));
});
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
test('ProxyProtocolV1#process overrides rinfo', async () => {
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
    const addr = Buffer.alloc(36);
    addr.writeUInt16BE(0x2001, 0);
    addr.writeUInt16BE(0x0db8, 2);
    addr.writeUInt16BE(0x0001, 14);
    addr.writeUInt16BE(0x2001, 16);
    addr.writeUInt16BE(0x0db8, 18);
    addr.writeUInt16BE(0x0002, 30);
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
    const control = Buffer.from([0x20, 0x00, 0x00, 0x00]);
    const parsed = ProxyProtocolV2.parse(Buffer.concat([ProxyProtocolV2.SIGNATURE, control]));
    assert.equal(parsed.info.command, ProxyProtocolCommand.LOCAL);
    assert.equal(parsed.info.source, undefined);
    assert.equal(parsed.info.destination, undefined);
});
test('ProxyProtocolV2#parse skips TLVs beyond address block', () => {
    const addrBlock = Buffer.from([
        1, 2, 3, 4,
        5, 6, 7, 8,
        0x00, 0x35,
        0x00, 0x50
    ]);
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
    assert.equal(ProxyProtocolV2.bytesNeeded(Buffer.alloc(4)), null);
    assert.equal(ProxyProtocolV2.bytesNeeded(ProxyProtocolV2.SIGNATURE), null);
    const header = Buffer.concat([
        ProxyProtocolV2.SIGNATURE,
        Buffer.from([0x21, 0x11, 0x00, 0x0C])
    ]);
    assert.equal(ProxyProtocolV2.bytesNeeded(header), 16 + 12);
    const bad = Buffer.from([0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0xFF]);
    assert.throws(() => ProxyProtocolV2.bytesNeeded(bad));
});
test('ProxyProtocolV2#process overrides rinfo', async () => {
    const control = Buffer.from([
        0x21, 0x12, 0x00, 0x0C,
        203, 0, 113, 7,
        198, 51, 100, 1,
        0xC3, 0x50,
        0x00, 0x35
    ]);
    const payload = Buffer.from([0xAA, 0xBB]);
    const handler = new ProxyProtocolV2();
    const result = await handler.process(Buffer.concat([ProxyProtocolV2.SIGNATURE, control, payload]), { address: '127.0.0.1', port: 12345, family: 'IPv4', size: 0 });
    assert.deepEqual(result.data, payload);
    assert.equal(result.client?.address, '203.0.113.7');
    assert.equal(result.client?.port, 50000);
    assert.equal(result.client?.family, 'IPv4');
});
const get = (url, options) => {
    return new Promise((resolve, reject) => {
        try {
            const req = http.get(url, options || {}, (res) => {
                const result = [];
                res.on('data', (data) => result.push(data));
                res.once('error', reject);
                res.once('end', () => resolve({
                    body: Buffer.concat(result),
                    headers: res.headers,
                }));
            });
            req.on('error', reject);
        }
        catch (err) {
            reject(err);
        }
    });
};
test('server/doh#cors - default', async () => {
    const server = new DohServer();
    const address = await new Promise((resolve) => {
        server.on('listening', resolve);
        server.listen(0);
    });
    const { headers } = await get(`http://localhost:${address.port}`);
    assert.equal(headers['access-control-allow-origin'], '*');
    server.close();
});
test('server/doh#cors - no cors', async () => {
    const server = new DohServer({ doh: { cors: false } });
    const address = await new Promise((resolve) => {
        server.on('listening', resolve);
        server.listen(0);
    });
    const { headers } = await get(`http://localhost:${address.port}`);
    assert.equal(headers['access-control-allow-origin'], undefined);
    server.close();
});
test('server/doh#cors - cors origin', async () => {
    const server = new DohServer({ doh: { cors: 'some.domain' } });
    const address = await new Promise((resolve) => {
        server.on('listening', resolve);
        server.listen(0);
    });
    const { headers } = await get(`http://localhost:${address.port}`);
    assert.equal(headers['access-control-allow-origin'], 'some.domain');
    assert.equal(headers.vary, 'Origin');
    server.close();
});
test('server/doh#cors - cors function', async () => {
    const server = new DohServer({
        doh: {
            cors: async (domain) => {
                if (domain === 'a.domain') {
                    return true;
                }
                else if (domain === 'b.domain') {
                    return false;
                }
                throw new Error(`Unexpected domain: ${domain}`);
            }
        }
    });
    const address = await new Promise((resolve) => {
        server.on('listening', resolve);
        server.listen(0);
    });
    let headers = (await get(`http://localhost:${address.port}`, { headers: { origin: 'a.domain' } })).headers;
    assert.equal(headers['access-control-allow-origin'], 'a.domain');
    assert.equal(headers.vary, 'Origin');
    headers = (await get(`http://localhost:${address.port}`, { headers: { origin: 'b.domain' } })).headers;
    assert.equal(headers['access-control-allow-origin'], 'false');
    assert.equal(headers.vary, 'Origin');
    server.close();
});
test('server/udp-tcp#simple-request-async-response', async () => {
    const server = new DnsServer({
        tcp: true,
        udp: true,
        handle: (request, send) => {
            const [question] = request.questions;
            assert.equal(question.name, 'test.com');
            assert.equal(question.type, PacketTypes.A);
            assert.equal(question.class, PacketClass.IN);
            const pResponse = Packet.createResponseFromRequest(request);
            pResponse.answers.push(new PacketResource(question.name, new TXT('Hello World'), PacketClass.IN, 300));
            new Promise((resolve) => { setTimeout(() => { resolve(); }, 1); }).then(() => send(pResponse));
        },
    });
    const servers = await server.listen();
    assert.ok(servers.udp && servers.udp.port > 1000);
    assert.ok(servers.tcp && servers.tcp.port > 1000);
    const tcpResolve = TCPClient.request({ dns: '127.0.0.1', port: servers.tcp.port });
    const udpResolve = UDPClient.request({ dns: '127.0.0.1', port: servers.udp.port });
    const tcpResult = await tcpResolve('test.com', PacketTypes.A, PacketClass.IN);
    assert.equal(tcpResult.answers.length, 1);
    assert.equal(tcpResult.answers[0].name, 'test.com');
    assert.equal(tcpResult.answers[0].ttl, 300);
    assert.equal(tcpResult.answers[0].packetType.data, 'Hello World');
    const udpResult = await udpResolve('test.com', PacketTypes.A, PacketClass.IN);
    assert.equal(udpResult.answers.length, 1);
    assert.equal(udpResult.answers[0].packetType.data, 'Hello World');
    await server.close();
});
test('server/tcp#proxy-protocol-v2', async () => {
    const captured = {};
    const server = new DnsServer({
        tcp: { preConnection: new ProxyProtocolV2Tcp() },
        handle: (request, send, client) => {
            const socket = client;
            captured.address = socket.remoteAddress;
            captured.port = socket.remotePort;
            const pResponse = Packet.createResponseFromRequest(request);
            pResponse.answers.push(new PacketResource(request.questions[0].name, new A('1.2.3.4'), PacketClass.IN, 300));
            send(pResponse);
        },
    });
    const addresses = await server.listen();
    const port = addresses.tcp.port;
    const proxyControl = Buffer.from([
        0x21, 0x11, 0x00, 0x0C,
        198, 51, 100, 7,
        203, 0, 113, 1,
        0xC3, 0x50,
        0x00, 0x35
    ]);
    const proxyHeader = Buffer.concat([ProxyProtocolV2.SIGNATURE, proxyControl]);
    const request = new Packet();
    request.header.id = 0x1234;
    request.header.rd = 1;
    request.questions.push(new PacketQuestion('example.com', PacketTypes.A, PacketClass.IN));
    const dnsBuf = request.toBuffer();
    const lenPrefix = Buffer.alloc(2);
    lenPrefix.writeUInt16BE(dnsBuf.length);
    const conn = tcp.connect({ port: port, host: '127.0.0.1' });
    await new Promise((resolve, reject) => {
        conn.once('connect', () => resolve());
        conn.once('error', reject);
    });
    conn.write(Buffer.concat([proxyHeader, lenPrefix, dnsBuf]));
    const responseBuf = await new Promise((resolve, reject) => {
        const chunks = [];
        conn.on('data', (c) => chunks.push(c));
        conn.on('end', () => resolve(Buffer.concat(chunks)));
        conn.on('error', reject);
    });
    const respLen = responseBuf.readUInt16BE(0);
    assert.equal(responseBuf.length, 2 + respLen);
    const respPacket = Packet.parse(responseBuf.subarray(2));
    assert.equal(respPacket.header.id, 0x1234);
    assert.equal(respPacket.answers.length, 1);
    assert.equal(respPacket.answers[0].packetType.address, '1.2.3.4');
    assert.equal(captured.address, '198.51.100.7');
    assert.equal(captured.port, 50000);
    await server.close();
});
test('server/tcp#proxy-protocol-v1', async () => {
    const captured = {};
    const server = new DnsServer({
        tcp: { preConnection: new ProxyProtocolV1Tcp() },
        handle: (request, send, client) => {
            const socket = client;
            captured.address = socket.remoteAddress;
            captured.port = socket.remotePort;
            const pResponse = Packet.createResponseFromRequest(request);
            pResponse.answers.push(new PacketResource(request.questions[0].name, new A('4.3.2.1'), PacketClass.IN, 300));
            send(pResponse);
        },
    });
    const addresses = await server.listen();
    const port = addresses.tcp.port;
    const proxyHeader = Buffer.from('PROXY TCP4 10.20.30.40 127.0.0.1 43210 53\r\n');
    const request = new Packet();
    request.header.id = 0x9ABC;
    request.header.rd = 1;
    request.questions.push(new PacketQuestion('foo.local', PacketTypes.A, PacketClass.IN));
    const dnsBuf = request.toBuffer();
    const lenPrefix = Buffer.alloc(2);
    lenPrefix.writeUInt16BE(dnsBuf.length);
    const conn = tcp.connect({ port: port, host: '127.0.0.1' });
    await new Promise((resolve, reject) => {
        conn.once('connect', () => resolve());
        conn.once('error', reject);
    });
    conn.write(Buffer.concat([proxyHeader, lenPrefix, dnsBuf]));
    const responseBuf = await new Promise((resolve, reject) => {
        const chunks = [];
        conn.on('data', (c) => chunks.push(c));
        conn.on('end', () => resolve(Buffer.concat(chunks)));
        conn.on('error', reject);
    });
    const respPacket = Packet.parse(responseBuf.subarray(2));
    assert.equal(respPacket.header.id, 0x9ABC);
    assert.equal(respPacket.answers[0].packetType.address, '4.3.2.1');
    assert.equal(captured.address, '10.20.30.40');
    assert.equal(captured.port, 43210);
    await server.close();
});
test('client/udp#tcp-fallback-on-truncation', async () => {
    let udpHits = 0;
    let tcpHits = 0;
    const server = new DnsServer({
        udp: true,
        tcp: true,
        handle: (request, send, client) => {
            const pResponse = Packet.createResponseFromRequest(request);
            if (client instanceof tcp.Socket) {
                tcpHits++;
                pResponse.answers.push(new PacketResource(request.questions[0].name, new A('9.9.9.9'), PacketClass.IN, 300));
                send(pResponse);
            }
            else {
                udpHits++;
                pResponse.header.tc = 1;
                send(pResponse);
            }
        },
    });
    const addresses = await server.listen();
    const udpPort = addresses.udp.port;
    const tcpPort = addresses.tcp.port;
    const resolve = UDPClient.request({
        dns: '127.0.0.1',
        port: udpPort,
        tcpFallbackPort: tcpPort
    });
    const result = await resolve('fallback.test', PacketTypes.A, PacketClass.IN);
    assert.equal(udpHits, 1);
    assert.equal(tcpHits, 1);
    assert.equal(result.header.tc, 0);
    assert.equal(result.answers.length, 1);
    assert.equal(result.answers[0].packetType.address, '9.9.9.9');
    await server.close();
});
test('client/udp#tcp-fallback-disabled returns truncated', async () => {
    const server = new DnsServer({
        udp: true,
        tcp: true,
        handle: (request, send, client) => {
            const pResponse = Packet.createResponseFromRequest(request);
            if (client instanceof tcp.Socket) {
                send(pResponse);
            }
            else {
                pResponse.header.tc = 1;
                send(pResponse);
            }
        },
    });
    const addresses = await server.listen();
    const udpPort = addresses.udp.port;
    const tcpPort = addresses.tcp.port;
    const resolve = UDPClient.request({
        dns: '127.0.0.1',
        port: udpPort,
        tcpFallbackPort: tcpPort,
        tcpFallback: false
    });
    const result = await resolve('fallback.test', PacketTypes.A, PacketClass.IN);
    assert.equal(result.header.tc, 1);
    assert.equal(result.answers.length, 0);
    await server.close();
});
test('server/all#invalid-request', async () => {
    const server = new DnsServer({
        doh: true,
        tcp: true,
        udp: true,
        handle: () => { },
    });
    const servers = await server.listen();
    assert.ok(servers.udp && servers.udp.port > 1000);
    assert.ok(servers.tcp && servers.tcp.port > 1000);
    assert.ok(servers.doh);
    const errors = [];
    server.on('requestError', (e) => {
        errors.push(e);
    });
    server.on('error', (e) => {
        errors.push(e);
    });
    const tcpPort = servers.tcp.port;
    const udpPort = servers.udp.port;
    const dohPort = servers.doh.port;
    const tcpSocket = tcp.connect({ port: tcpPort, host: '127.0.0.1' });
    tcpSocket.on('connect', () => tcpSocket.end('INVALID'));
    const udpSocket = dgram.createSocket('udp4');
    udpSocket.send('INVALID', udpPort, '127.0.0.1', () => udpSocket.close());
    const dohConn = http.get(`http://127.0.0.1:${dohPort}/dns-query?dns=INVALID`, {
        headers: { accept: 'application/dns-message' },
    }).on('error', () => { });
    await Promise.all([
        new Promise((resolve) => { tcpSocket.on('close', resolve); }),
        new Promise((resolve) => { udpSocket.on('close', resolve); }),
        new Promise((resolve) => { dohConn.on('close', resolve); }),
    ]);
    assert.equal(errors.length, 3);
    await server.close();
});
//# sourceMappingURL=index.js.map