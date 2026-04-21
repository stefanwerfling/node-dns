import assert from 'assert';
import http from 'http';
import tcp from 'net';
import dgram from 'dgram';
import {AddressInfo} from 'net';
import {test} from './test.js';
import {BufferReader} from '../Lib/BufferReader.js';
import {IP} from '../Packet/IP.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketHeader} from '../Packet/PacketHeader.js';
import {PacketName} from '../Packet/PacketName.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {AAAA} from '../Packet/Types/AAAA.js';
import {CNAME} from '../Packet/Types/CNAME.js';
import {DNSKEY} from '../Packet/Types/DNSKEY.js';
import {EDNS, EdnsECS} from '../Packet/Types/EDNS.js';
import {MX} from '../Packet/Types/MX.js';
import {NS} from '../Packet/Types/NS.js';
import {PTR} from '../Packet/Types/PTR.js';
import {SOA} from '../Packet/Types/SOA.js';
import {TXT} from '../Packet/Types/TXT.js';
import {DnsServer} from '../Server/DnsServer.js';
import {DohServer} from '../Server/DohServer.js';
import {TCPClient} from '../Client/TCPClient.js';
import {UDPClient} from '../Client/UDPClient.js';

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
        '2a04', '4e42', '0200', '0', '0', '0', '0', '0323']);
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
    assert.equal((parsed.answers[0].packetType as TXT).data, dkim.join(''));
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
    const edns = EDNS.decode(reader, buffer.length) as EDNS;

    assert.equal(edns.rdata.length, 1);

    const ecs = edns.rdata[0] as EdnsECS;
    assert.equal(ecs.ednsCode, 8);
    assert.equal(ecs.family, 1);
    assert.equal(ecs.sourcePrefixLength, 24);
    assert.equal(ecs.scopePrefixLength, 0);
    assert.equal(ecs.ip, '10.11.12.13');

    // Roundtrip test
    const resource = EDNS.createResource([new EdnsECS('10.20.0.0/16')]);
    const encoded = PacketResource.encode(resource);
    const decoded = PacketResource.decode(encoded);
    const decodedEdns = decoded.packetType as EDNS;
    const decodedEcs = decodedEdns.rdata[0] as EdnsECS;
    const originalEcs = (resource.packetType as EDNS).rdata[0] as EdnsECS;
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
    const decodedEdns = decoded.packetType as EDNS;

    assert.equal(decodedEdns.rdata.length, 4);
    assert.equal((decodedEdns.rdata[0] as EdnsECS).ip, '10.0.0.0');
    assert.equal((decodedEdns.rdata[0] as EdnsECS).sourcePrefixLength, 8);
    assert.equal((decodedEdns.rdata[1] as EdnsECS).ip, '10.9.0.0');
    assert.equal((decodedEdns.rdata[2] as EdnsECS).ip, '10.9.8.0');
    assert.equal((decodedEdns.rdata[3] as EdnsECS).ip, '10.9.8.7');
    assert.equal((decodedEdns.rdata[3] as EdnsECS).sourcePrefixLength, 32);
});

// -- HTTP helper --

const get = (url: string, options?: http.RequestOptions): Promise<{body: Buffer; headers: http.IncomingHttpHeaders}> => {
    return new Promise((resolve, reject) => {
        try {
            const req = http.get(url, options || {}, (res) => {
                const result: Buffer[] = [];

                res.on('data', (data: Buffer) => result.push(data));
                res.once('error', reject);
                res.once('end', () => resolve({
                    body: Buffer.concat(result),
                    headers: res.headers,
                }));
            });

            req.on('error', reject);
        } catch (err) {
            reject(err);
        }
    });
};

// -- DohServer CORS tests --

test('server/doh#cors - default', async() => {
    const server = new DohServer();
    const address = await new Promise<AddressInfo>((resolve) => {
        server.on('listening', resolve);
        server.listen(0);
    });
    const {headers} = await get(`http://localhost:${address.port}`);
    assert.equal(headers['access-control-allow-origin'], '*');
    server.close();
});

test('server/doh#cors - no cors', async() => {
    const server = new DohServer({doh: {cors: false}});
    const address = await new Promise<AddressInfo>((resolve) => {
        server.on('listening', resolve);
        server.listen(0);
    });
    const {headers} = await get(`http://localhost:${address.port}`);
    assert.equal(headers['access-control-allow-origin'], undefined);
    server.close();
});

test('server/doh#cors - cors origin', async() => {
    const server = new DohServer({doh: {cors: 'some.domain'}});
    const address = await new Promise<AddressInfo>((resolve) => {
        server.on('listening', resolve);
        server.listen(0);
    });
    const {headers} = await get(`http://localhost:${address.port}`);
    assert.equal(headers['access-control-allow-origin'], 'some.domain');
    assert.equal(headers.vary, 'Origin');
    server.close();
});

test('server/doh#cors - cors function', async() => {
    const server = new DohServer({
        doh: {
            cors: async(domain): Promise<boolean> => {
                if (domain === 'a.domain') {
                    return true;
                } else if (domain === 'b.domain') {
                    return false;
                }

                throw new Error(`Unexpected domain: ${domain}`);
            }
        }
    });
    const address = await new Promise<AddressInfo>((resolve) => {
        server.on('listening', resolve);
        server.listen(0);
    });

    let headers = (await get(`http://localhost:${address.port}`, {headers: {origin: 'a.domain'}})).headers;
    assert.equal(headers['access-control-allow-origin'], 'a.domain');
    assert.equal(headers.vary, 'Origin');

    headers = (await get(`http://localhost:${address.port}`, {headers: {origin: 'b.domain'}})).headers;
    assert.equal(headers['access-control-allow-origin'], 'false');
    assert.equal(headers.vary, 'Origin');

    server.close();
});

// -- Integration tests --

test('server/udp-tcp#simple-request-async-response', async() => {
    const server = new DnsServer({
        tcp: true,
        udp: true,
        handle(request, send): void {
            const [question] = request.questions;
            assert.equal(question.name, 'test.com');
            assert.equal(question.type, PacketTypes.A);
            assert.equal(question.class, PacketClass.IN);

            const pResponse = Packet.createResponseFromRequest(request);
            pResponse.answers.push(
                new PacketResource(question.name, new TXT('Hello World'), PacketClass.IN, 300)
            );

            void new Promise<void>((resolve) => setTimeout(() => resolve(), 1)).then(() => send(pResponse));
        },
    });

    const servers = await server.listen();
    assert.ok(servers.udp && servers.udp.port > 1000);
    assert.ok(servers.tcp && (servers.tcp as AddressInfo).port > 1000);

    const tcpResolve = TCPClient.request({dns: '127.0.0.1', port: (servers.tcp as AddressInfo).port});
    const udpResolve = UDPClient.request({dns: '127.0.0.1', port: servers.udp!.port});

    const tcpResult = await tcpResolve('test.com', PacketTypes.A, PacketClass.IN);
    assert.equal(tcpResult.answers.length, 1);
    assert.equal(tcpResult.answers[0].name, 'test.com');
    assert.equal(tcpResult.answers[0].ttl, 300);
    assert.equal((tcpResult.answers[0].packetType as TXT).data, 'Hello World');

    const udpResult = await udpResolve('test.com', PacketTypes.A, PacketClass.IN);
    assert.equal(udpResult.answers.length, 1);
    assert.equal((udpResult.answers[0].packetType as TXT).data, 'Hello World');

    await server.close();
});

test('server/all#invalid-request', async() => {
    const server = new DnsServer({
        doh: true,
        tcp: true,
        udp: true,
        handle: (): void => {},
    });

    const servers = await server.listen();
    assert.ok(servers.udp && servers.udp.port > 1000);
    assert.ok(servers.tcp && (servers.tcp as AddressInfo).port > 1000);
    assert.ok(servers.doh);

    const errors: unknown[] = [];

    server.on('requestError', (e: unknown) => {
        errors.push(e);
    });

    server.on('error', (e: unknown) => {
        errors.push(e);
    });

    const tcpPort = (servers.tcp as AddressInfo).port;
    const udpPort = servers.udp!.port;
    const dohPort = (servers.doh as AddressInfo).port;

    const tcpSocket = tcp.connect({port: tcpPort, host: '127.0.0.1'});
    tcpSocket.on('connect', () => tcpSocket.end('INVALID'));

    const udpSocket = dgram.createSocket('udp4');
    udpSocket.send('INVALID', udpPort, '127.0.0.1', () => udpSocket.close());

    const dohConn = http.get(`http://127.0.0.1:${dohPort}/dns-query?dns=INVALID`, {
        headers: {accept: 'application/dns-message'},
    }).on('error', () => {});

    await Promise.all([
        new Promise<void>((resolve) => tcpSocket.on('close', resolve)),
        new Promise<void>((resolve) => udpSocket.on('close', resolve)),
        new Promise<void>((resolve) => dohConn.on('close', resolve)),
    ]);

    assert.equal(errors.length, 3);

    await server.close();
});