import assert from 'assert';
import dgram from 'dgram';
import http from 'http';
import tcp from 'net';
import { TCPClient } from '../Client/TCPClient.js';
import { UDPClient } from '../Client/UDPClient.js';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { TXT } from '../Packet/Types/TXT.js';
import { DnsServer } from '../Server/DnsServer.js';
import { ProxyProtocolV1Tcp } from '../Server/ProxyProtocol/ProxyProtocolV1Tcp.js';
import { ProxyProtocolV2 } from '../Server/ProxyProtocol/ProxyProtocolV2.js';
import { ProxyProtocolV2Tcp } from '../Server/ProxyProtocol/ProxyProtocolV2Tcp.js';
import { test } from './test.js';
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
//# sourceMappingURL=serverIntegration.js.map