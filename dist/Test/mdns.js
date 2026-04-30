import assert from 'assert';
import dgram from 'dgram';
import { MdnsClient, MDNS_QU_BIT, MDNS_CACHE_FLUSH_BIT } from '../Client/MdnsClient.js';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { test } from './test.js';
const bindLocalResponder = async () => {
    return new Promise((resolve, reject) => {
        const socket = dgram.createSocket('udp4');
        socket.once('error', reject);
        socket.bind(0, '127.0.0.1', () => {
            const addr = socket.address();
            resolve({ socket: socket, port: addr.port });
        });
    });
};
test('MdnsClient#makeQuery sets the QU bit when unicastResponse is true', () => {
    const q = MdnsClient.makeQuery('printer.local', PacketTypes.A, PacketClass.IN, true);
    assert.equal(q.questions[0].class & MDNS_QU_BIT, MDNS_QU_BIT);
    assert.equal(q.questions[0].class & ~MDNS_QU_BIT, PacketClass.IN);
});
test('MdnsClient#makeQuery leaves the QU bit clear by default', () => {
    const q = MdnsClient.makeQuery('printer.local', PacketTypes.A);
    assert.equal(q.questions[0].class & MDNS_QU_BIT, 0);
});
test('MdnsClient#makeQuery uses ID=0 per RFC 6762 §18.1', () => {
    const q = MdnsClient.makeQuery('printer.local', PacketTypes.A);
    assert.equal(q.header.id, 0);
});
test('MdnsClient#request collects a response from a local responder', async () => {
    const { socket: responder, port: responderPort } = await bindLocalResponder();
    responder.on('message', (msg, rinfo) => {
        const query = Packet.parse(msg);
        const reply = new Packet();
        reply.header.qr = 1;
        reply.header.aa = 1;
        reply.questions = query.questions.slice();
        reply.answers = [
            new PacketResource('printer.local', new A('192.168.1.5'), PacketClass.IN, 120)
        ];
        responder.send(reply.toBuffer(), rinfo.port, rinfo.address);
    });
    try {
        const resolve = MdnsClient.request({
            multicastAddr: '127.0.0.1',
            port: responderPort,
            timeoutMs: 200
        });
        const results = await resolve('printer.local', PacketTypes.A);
        assert.equal(results.length, 1);
        assert.equal(results[0].answers.length, 1);
        assert.equal(results[0].answers[0].packetType.address, '192.168.1.5');
        assert.equal(results[0].sender.address, '127.0.0.1');
        assert.equal(results[0].sender.port, responderPort);
    }
    finally {
        responder.close();
    }
});
test('MdnsClient#request collects responses from multiple responders', async () => {
    const r1 = await bindLocalResponder();
    const r2 = await bindLocalResponder();
    r1.socket.on('message', (msg, rinfo) => {
        const query = Packet.parse(msg);
        const reply = new Packet();
        reply.header.qr = 1;
        reply.header.aa = 1;
        reply.questions = query.questions.slice();
        reply.answers = [
            new PacketResource('shared.local', new A('192.168.1.5'), PacketClass.IN, 120)
        ];
        r1.socket.send(reply.toBuffer(), rinfo.port, rinfo.address);
        r2.socket.send(reply.toBuffer(), rinfo.port, rinfo.address);
    });
    try {
        const resolve = MdnsClient.request({
            multicastAddr: '127.0.0.1',
            port: r1.port,
            timeoutMs: 200
        });
        const results = await resolve('shared.local', PacketTypes.A);
        assert.equal(results.length, 2, 'mDNS aggregates responses from every device that answers');
    }
    finally {
        r1.socket.close();
        r2.socket.close();
    }
});
test('MdnsClient#request times out cleanly when no one answers', async () => {
    const { socket, port } = await bindLocalResponder();
    socket.close();
    const resolve = MdnsClient.request({
        multicastAddr: '127.0.0.1',
        port: port,
        timeoutMs: 80
    });
    const start = Date.now();
    const results = await resolve('absent.local', PacketTypes.A);
    const elapsed = Date.now() - start;
    assert.deepEqual(results, []);
    assert.ok(elapsed >= 70, `expected at least 70ms wait, got ${elapsed}ms`);
});
test('MdnsClient#request ignores malformed datagrams from the multicast group', async () => {
    const { socket: responder, port: responderPort } = await bindLocalResponder();
    let firstMessage = true;
    responder.on('message', (_msg, rinfo) => {
        if (firstMessage) {
            firstMessage = false;
            responder.send(Buffer.from([0xff, 0xff, 0xff]), rinfo.port, rinfo.address);
            const reply = new Packet();
            reply.header.qr = 1;
            reply.header.aa = 1;
            reply.answers = [
                new PacketResource('printer.local', new A('10.0.0.1'), PacketClass.IN, 120)
            ];
            responder.send(reply.toBuffer(), rinfo.port, rinfo.address);
        }
    });
    try {
        const resolve = MdnsClient.request({
            multicastAddr: '127.0.0.1',
            port: responderPort,
            timeoutMs: 200
        });
        const results = await resolve('printer.local', PacketTypes.A);
        assert.equal(results.length, 1, 'malformed datagram was filtered out, valid one collected');
        assert.equal(results[0].answers[0].packetType.address, '10.0.0.1');
    }
    finally {
        responder.close();
    }
});
test('MdnsClient#request ignores echoed queries (qr=0) from the same group', async () => {
    const { socket: responder, port: responderPort } = await bindLocalResponder();
    responder.on('message', (msg, rinfo) => {
        responder.send(msg, rinfo.port, rinfo.address);
    });
    try {
        const resolve = MdnsClient.request({
            multicastAddr: '127.0.0.1',
            port: responderPort,
            timeoutMs: 100
        });
        const results = await resolve('printer.local', PacketTypes.A);
        assert.deepEqual(results, [], 'echoed queries (qr=0) must not surface as responses');
    }
    finally {
        responder.close();
    }
});
test('MdnsClient#cache-flush bit constant is 0x8000 — RFC 6762 §10.2', () => {
    assert.equal(MDNS_CACHE_FLUSH_BIT, 0x8000);
});
//# sourceMappingURL=mdns.js.map