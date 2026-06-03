import assert from 'assert';
import { Buffer } from 'buffer';
import dgram from 'dgram';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { EDNS } from '../Packet/Types/EDNS.js';
import { EdnsCookie } from '../Packet/Types/EdnsCookie.js';
import { UDPServer } from '../Server/UDPServer.js';
import { test } from './test.js';
const SECRET = Buffer.from('this-is-a-test-secret-must-be-stable', 'utf8');
const buildQuery = (id, name, cookieOption) => {
    const p = new Packet();
    p.header.id = id;
    p.header.rd = 1;
    p.questions.push(new PacketQuestion(name, PacketTypes.A, PacketClass.IN));
    if (cookieOption !== undefined) {
        p.additionals.push(EDNS.createResource([cookieOption], 1232, false));
    }
    return p.toBuffer();
};
const sendAndRecv = (port, payload) => {
    return new Promise((resolve, reject) => {
        const socket = dgram.createSocket('udp4');
        const cleanup = () => {
            socket.removeAllListeners();
            socket.close();
        };
        const timer = setTimeout(() => {
            cleanup();
            reject(new Error('sendAndRecv timeout'));
        }, 1500);
        timer.unref?.();
        socket.once('message', (raw) => {
            clearTimeout(timer);
            cleanup();
            resolve({ response: Packet.parse(raw), raw: raw });
        });
        socket.once('error', (e) => {
            clearTimeout(timer);
            cleanup();
            reject(e);
        });
        socket.send(payload, port, '127.0.0.1');
    });
};
const startServer = async (cookies) => {
    const server = new UDPServer({ udp: { cookies: cookies } });
    const received = [];
    const rejected = [];
    server.on('request', (msg, send) => {
        received.push(msg);
        const reply = new Packet();
        reply.header.id = msg.header.id;
        reply.header.qr = 1;
        reply.header.rd = msg.header.rd;
        reply.questions = msg.questions.slice();
        reply.answers = [new PacketResource(msg.questions[0].name, new A('192.0.2.1'), PacketClass.IN, 60)];
        send(reply);
    });
    server.on('cookieRejected', (_msg, _rinfo, reason) => {
        rejected.push(reason);
    });
    await server.listen(0, '127.0.0.1');
    const port = server.address().port;
    return { server: server, port: port, received: received, rejected: rejected };
};
const findCookieOption = (packet) => {
    for (const r of packet.additionals) {
        if (r.packetType.type !== PacketTypes.EDNS)
            continue;
        for (const opt of r.packetType.rdata) {
            if (opt instanceof EdnsCookie)
                return opt;
        }
    }
    return null;
};
test('UDPServer cookies: query without cookie passes through (lenient mode)', async () => {
    const { server, port, received, rejected } = await startServer({ secret: SECRET });
    try {
        const { response } = await sendAndRecv(port, buildQuery(0x1234, 'host.test'));
        assert.equal(response.header.rcode, 0);
        assert.equal(response.answers.length, 1);
        assert.equal(received.length, 1);
        assert.equal(rejected.length, 0);
    }
    finally {
        await new Promise((resolve) => server.close(() => resolve()));
    }
});
test('UDPServer cookies: client-only cookie gets BADCOOKIE with fresh server cookie', async () => {
    const { server, port, received, rejected } = await startServer({ secret: SECRET });
    try {
        const clientCookie = EdnsCookie.generateClientCookie();
        const { response } = await sendAndRecv(port, buildQuery(0x1234, 'host.test', new EdnsCookie(clientCookie)));
        assert.equal(response.header.rcode, 7);
        assert.equal(received.length, 0, 'handler must NOT see rejected query');
        assert.deepEqual(rejected, ['no-server-cookie']);
        const cookie = findCookieOption(response);
        assert.ok(cookie !== null, 'response carries cookie option');
        assert.ok(cookie.serverCookie !== null, 'fresh server cookie issued');
        assert.deepEqual(Array.from(cookie.clientCookie), Array.from(clientCookie));
    }
    finally {
        await new Promise((resolve) => server.close(() => resolve()));
    }
});
test('UDPServer cookies: BADCOOKIE response carries extended RCODE in OPT TTL', async () => {
    const { server, port } = await startServer({ secret: SECRET });
    try {
        const { response } = await sendAndRecv(port, buildQuery(1, 'host.test', new EdnsCookie(EdnsCookie.generateClientCookie())));
        const opt = response.additionals.find((r) => r.packetType.type === PacketTypes.EDNS);
        assert.ok(opt !== undefined);
        assert.equal((opt.ttl >>> 24) & 0xFF, 1);
    }
    finally {
        await new Promise((resolve) => server.close(() => resolve()));
    }
});
test('UDPServer cookies: valid server cookie passes through + response refreshes cookie', async () => {
    const { server, port, received } = await startServer({ secret: SECRET });
    try {
        const clientCookie = EdnsCookie.generateClientCookie();
        const validServer = EdnsCookie.computeServerCookie(clientCookie, Buffer.from([127, 0, 0, 1]), SECRET);
        const { response } = await sendAndRecv(port, buildQuery(7, 'host.test', new EdnsCookie(clientCookie, validServer)));
        assert.equal(response.header.rcode, 0);
        assert.equal(received.length, 1, 'handler saw the valid query');
        assert.equal(response.answers.length, 1);
        const cookie = findCookieOption(response);
        assert.ok(cookie !== null);
        assert.deepEqual(Array.from(cookie.clientCookie), Array.from(clientCookie));
        assert.ok(cookie.serverCookie !== null);
        assert.ok(EdnsCookie.verifyServerCookie(cookie.serverCookie, cookie.clientCookie, Buffer.from([127, 0, 0, 1]), SECRET));
    }
    finally {
        await new Promise((resolve) => server.close(() => resolve()));
    }
});
test('UDPServer cookies: tampered server cookie gets BADCOOKIE', async () => {
    const { server, port, received, rejected } = await startServer({ secret: SECRET });
    try {
        const clientCookie = EdnsCookie.generateClientCookie();
        const valid = EdnsCookie.computeServerCookie(clientCookie, Buffer.from([127, 0, 0, 1]), SECRET);
        const tampered = Buffer.from(valid);
        tampered[12] ^= 0x01;
        const { response } = await sendAndRecv(port, buildQuery(8, 'host.test', new EdnsCookie(clientCookie, tampered)));
        assert.equal(response.header.rcode, 7, 'BADCOOKIE low nibble');
        assert.equal(received.length, 0);
        assert.deepEqual(rejected, ['invalid-cookie']);
    }
    finally {
        await new Promise((resolve) => server.close(() => resolve()));
    }
});
test('UDPServer cookies: strict mode REFUSES a query without any cookie', async () => {
    const { server, port, received, rejected } = await startServer({ secret: SECRET, mode: 'strict' });
    try {
        const { response } = await sendAndRecv(port, buildQuery(9, 'host.test'));
        assert.equal(response.header.rcode, 5);
        assert.equal(received.length, 0);
        assert.deepEqual(rejected, ['no-cookie-strict']);
    }
    finally {
        await new Promise((resolve) => server.close(() => resolve()));
    }
});
test('UDPServer cookies: strict mode still accepts a query with a valid cookie', async () => {
    const { server, port, received } = await startServer({ secret: SECRET, mode: 'strict' });
    try {
        const clientCookie = EdnsCookie.generateClientCookie();
        const valid = EdnsCookie.computeServerCookie(clientCookie, Buffer.from([127, 0, 0, 1]), SECRET);
        const { response } = await sendAndRecv(port, buildQuery(10, 'host.test', new EdnsCookie(clientCookie, valid)));
        assert.equal(response.header.rcode, 0);
        assert.equal(received.length, 1);
    }
    finally {
        await new Promise((resolve) => server.close(() => resolve()));
    }
});
test('UDPServer cookies: expired server cookie gets BADCOOKIE under maxAgeSeconds', async () => {
    const { server, port, rejected } = await startServer({ secret: SECRET, maxAgeSeconds: 60 });
    try {
        const clientCookie = EdnsCookie.generateClientCookie();
        const stale = EdnsCookie.computeServerCookie(clientCookie, Buffer.from([127, 0, 0, 1]), SECRET, Math.floor(Date.now() / 1000) - 3600);
        const { response } = await sendAndRecv(port, buildQuery(11, 'host.test', new EdnsCookie(clientCookie, stale)));
        assert.equal(response.header.rcode, 7);
        assert.deepEqual(rejected, ['invalid-cookie']);
    }
    finally {
        await new Promise((resolve) => server.close(() => resolve()));
    }
});
test('UDPServer cookies: maxAgeSeconds=0 disables expiry check', async () => {
    const { server, port, received } = await startServer({ secret: SECRET, maxAgeSeconds: 0 });
    try {
        const clientCookie = EdnsCookie.generateClientCookie();
        const ancient = EdnsCookie.computeServerCookie(clientCookie, Buffer.from([127, 0, 0, 1]), SECRET, Math.floor(Date.now() / 1000) - 86400 * 30);
        const { response } = await sendAndRecv(port, buildQuery(12, 'host.test', new EdnsCookie(clientCookie, ancient)));
        assert.equal(response.header.rcode, 0);
        assert.equal(received.length, 1);
    }
    finally {
        await new Promise((resolve) => server.close(() => resolve()));
    }
});
test('UDPServer cookies: cookie option preserves other EDNS options in response', async () => {
    const server = new UDPServer({ udp: { cookies: { secret: SECRET } } });
    server.on('request', (msg, send) => {
        const reply = new Packet();
        reply.header.id = msg.header.id;
        reply.header.qr = 1;
        reply.questions = msg.questions.slice();
        reply.answers = [new PacketResource('host.test', new A('192.0.2.7'), PacketClass.IN, 60)];
        reply.additionals.push(EDNS.createResource([], 4096, false));
        send(reply);
    });
    await server.listen(0, '127.0.0.1');
    const port = server.address().port;
    try {
        const clientCookie = EdnsCookie.generateClientCookie();
        const valid = EdnsCookie.computeServerCookie(clientCookie, Buffer.from([127, 0, 0, 1]), SECRET);
        const { response } = await sendAndRecv(port, buildQuery(13, 'host.test', new EdnsCookie(clientCookie, valid)));
        const opt = response.additionals.find((r) => r.packetType.type === PacketTypes.EDNS);
        assert.ok(opt !== undefined);
        assert.equal(opt.class, 4096);
        const cookie = findCookieOption(response);
        assert.ok(cookie !== null);
        assert.deepEqual(Array.from(cookie.clientCookie), Array.from(clientCookie));
    }
    finally {
        await new Promise((resolve) => server.close(() => resolve()));
    }
});
//# sourceMappingURL=serverCookies.js.map