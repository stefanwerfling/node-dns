import assert from 'assert';
import dgram from 'dgram';
import { MdnsClient } from '../Client/MdnsClient.js';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { MdnsServer } from '../Server/MdnsServer.js';
import { test } from './test.js';
const aRec = (name, addr) => new PacketResource(name, new A(addr), PacketClass.IN, 120);
test('MdnsServer#fires request and the handler can reply unicast', async () => {
    const server = new MdnsServer({
        multicastAddr: '127.0.0.1',
        port: 0,
        interfaceAddress: '127.0.0.1'
    });
    server.on('request', (msg, send) => {
        const reply = new Packet();
        reply.header.qr = 1;
        reply.header.aa = 1;
        reply.questions = msg.questions.slice();
        reply.answers = [aRec('printer.local', '192.168.1.5')];
        void send(reply, 'unicast');
    });
    await server.listen();
    try {
        const port = server.address().port;
        const resolve = MdnsClient.request({
            multicastAddr: '127.0.0.1',
            port: port,
            timeoutMs: 200
        });
        const responses = await resolve('printer.local', PacketTypes.A);
        assert.equal(responses.length, 1);
        assert.equal(responses[0].answers[0].packetType.address, '192.168.1.5');
    }
    finally {
        server.close();
    }
});
test('MdnsServer#filters out responses (qr=1) — only queries fire request', async () => {
    const server = new MdnsServer({
        multicastAddr: '127.0.0.1',
        port: 0,
        interfaceAddress: '127.0.0.1'
    });
    let requestCount = 0;
    server.on('request', (_msg, _send) => {
        requestCount++;
    });
    await server.listen();
    const port = server.address().port;
    const sender = dgram.createSocket('udp4');
    await new Promise((r) => sender.bind(0, '127.0.0.1', () => r()));
    const fake = new Packet();
    fake.header.qr = 1;
    fake.header.aa = 1;
    fake.answers = [aRec('printer.local', '10.0.0.1')];
    sender.send(fake.toBuffer(), port, '127.0.0.1');
    const realQuery = new Packet();
    realQuery.header.qr = 0;
    realQuery.questions = [new PacketQuestion('printer.local', PacketTypes.A, PacketClass.IN)];
    sender.send(realQuery.toBuffer(), port, '127.0.0.1');
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(requestCount, 1, 'qr=1 must be filtered, qr=0 must fire');
    sender.close();
    server.close();
});
test('MdnsServer#malformed datagram triggers requestError, not request', async () => {
    const server = new MdnsServer({
        multicastAddr: '127.0.0.1',
        port: 0,
        interfaceAddress: '127.0.0.1'
    });
    let requestCount = 0;
    let errorCount = 0;
    server.on('request', () => {
        requestCount++;
    });
    server.on('requestError', () => {
        errorCount++;
    });
    await server.listen();
    const port = server.address().port;
    const sender = dgram.createSocket('udp4');
    await new Promise((r) => sender.bind(0, '127.0.0.1', () => r()));
    sender.send(Buffer.from([0xff, 0xff, 0xff, 0xff]), port, '127.0.0.1');
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(requestCount, 0);
    assert.equal(errorCount, 1);
    sender.close();
    server.close();
});
test('MdnsServer#auto target uses unicast when QU bit is set on the question', async () => {
    const server = new MdnsServer({
        multicastAddr: '127.0.0.1',
        port: 0,
        interfaceAddress: '127.0.0.1'
    });
    server.on('request', (msg, send) => {
        const reply = new Packet();
        reply.header.qr = 1;
        reply.header.aa = 1;
        reply.questions = msg.questions.slice();
        reply.answers = [aRec('printer.local', '192.168.1.5')];
        void send(reply);
    });
    await server.listen();
    const port = server.address().port;
    try {
        const resolve = MdnsClient.request({
            multicastAddr: '127.0.0.1',
            port: port,
            timeoutMs: 200,
            unicastResponse: true
        });
        const responses = await resolve('printer.local', PacketTypes.A);
        assert.equal(responses.length, 1);
        assert.equal(responses[0].answers[0].packetType.address, '192.168.1.5');
    }
    finally {
        server.close();
    }
});
test('MdnsServer#address() returns the bound port + address', async () => {
    const server = new MdnsServer({
        multicastAddr: '127.0.0.1',
        port: 0,
        interfaceAddress: '127.0.0.1'
    });
    await server.listen();
    try {
        const addr = server.address();
        assert.equal(addr.address, '127.0.0.1');
        assert.ok(addr.port > 0);
    }
    finally {
        server.close();
    }
});
test('MdnsServer#rawRequest matches the wire bytes (TSIG-friendly)', async () => {
    const server = new MdnsServer({
        multicastAddr: '127.0.0.1',
        port: 0,
        interfaceAddress: '127.0.0.1'
    });
    let observed = null;
    server.on('request', (_msg, _send, _rinfo, raw) => {
        observed = raw;
    });
    await server.listen();
    const port = server.address().port;
    const sender = dgram.createSocket('udp4');
    await new Promise((r) => sender.bind(0, '127.0.0.1', () => r()));
    const query = new Packet();
    query.header.qr = 0;
    query.questions = [new PacketQuestion('tv.local', PacketTypes.A, PacketClass.IN)];
    const wire = query.toBuffer();
    sender.send(wire, port, '127.0.0.1');
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.ok(observed);
    assert.deepEqual(observed, wire, 'rawRequest must equal the bytes that arrived on the wire');
    sender.close();
    server.close();
});
//# sourceMappingURL=mdnsServer.js.map