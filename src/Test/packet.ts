import assert from 'assert';
import {IP} from '../Packet/IP.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketHeader} from '../Packet/PacketHeader.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {AAAA} from '../Packet/Types/AAAA.js';
import {CNAME} from '../Packet/Types/CNAME.js';
import {DNSKEY} from '../Packet/Types/DNSKEY.js';
import {MX} from '../Packet/Types/MX.js';
import {NS} from '../Packet/Types/NS.js';
import {PTR} from '../Packet/Types/PTR.js';
import {SOA} from '../Packet/Types/SOA.js';
import {TXT} from '../Packet/Types/TXT.js';
import {response} from './helpers.js';
import {test} from './test.js';

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
    const question = new PacketQuestion(
        'google.com',
        PacketTypes.A,
        PacketClass.IN
    );
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

    const aRecord = packet.answers[0].packetType as A;
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
    packet.additionals.push(new PacketResource('lsong.org', new SOA(
        'lsong.org', 'admin@lsong.org', 2016121301, 300, 3, 10, 10
    ), PacketClass.IN, 300));
    packet.additionals.push(new PacketResource('lsong.org', new TXT(
        '#v=spf1 include:_spf.google.com ~all'
    ), PacketClass.IN, 300));

    const parsed = Packet.parse(packet.toBuffer());

    // Verify header
    assert.equal(parsed.header.qr, 1);
    assert.equal(parsed.answers.length, 5);
    assert.equal(parsed.authorities.length, 2);
    assert.equal(parsed.additionals.length, 2);

    // Verify answers
    assert.equal((parsed.answers[0].packetType as A).address, '127.0.0.1');
    assert.equal((parsed.answers[1].packetType as AAAA).address, '2001:db8::ff00:42:8329');
    assert.equal((parsed.answers[2].packetType as CNAME).domain, 'sfo1.lsong.org');
    assert.equal((parsed.answers[3].packetType as PTR).domain, 'sfo1.lsong.org');

    const parsedKey = parsed.answers[4].packetType as DNSKEY;
    assert.equal(parsedKey.flags, 256);
    assert.equal(parsedKey.protocol, 3);
    assert.equal(parsedKey.algorithm, 13);
    assert.equal(parsedKey.zoneKey, true);
    assert.equal(parsedKey.zoneSep, false);
    assert.equal(parsedKey.key, dnskey.key);

    // Verify authorities
    const mx = parsed.authorities[0].packetType as MX;
    assert.equal(mx.exchange, 'mail.lsong.org');
    assert.equal(mx.priority, 5);
    assert.equal((parsed.authorities[1].packetType as NS).ns, 'ns1.lsong.org');

    // Verify additionals
    const soa = parsed.additionals[0].packetType as SOA;
    assert.equal(soa.primary, 'lsong.org');
    assert.equal(soa.admin, 'admin@lsong.org');
    assert.equal(soa.serial, 2016121301);
    assert.equal((parsed.additionals[1].packetType as TXT).data, '#v=spf1 include:_spf.google.com ~all');
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
    // RFC 1035 §3.3.14 — TXT is "one or more <character-string>", and
    // the per-string boundaries are preserved in the decoded array
    // so RFC 6763 (DNS-SD) consumers can read each key=value entry
    // separately.
    assert.deepEqual((parsed.answers[0].packetType as TXT).data, dkim);
});