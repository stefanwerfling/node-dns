import assert from 'assert';
import { Buffer } from 'buffer';
import tcp from 'net';
import tls from 'tls';
import { ClientCookieJar } from '../Client/ClientCookieJar.js';
import { TCPClient } from '../Client/TCPClient.js';
import { ClientOptionsProtocol } from '../Client/ClientOptions.js';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { EDNS } from '../Packet/Types/EDNS.js';
import { EdnsCookie } from '../Packet/Types/EdnsCookie.js';
import { TCPServer } from '../Server/TCPServer.js';
import { TLSServer } from '../Server/TLSServer.js';
import { tlsCert, tlsKey } from './helpers.js';
import { test } from './test.js';
const SECRET = Buffer.from('tcp-cookie-test-secret-must-be-stable', 'utf8');
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
const frame = (payload) => {
    const len = Buffer.alloc(2);
    len.writeUInt16BE(payload.length);
    return Buffer.concat([len, payload]);
};
const tcpQuery = (port, payload) => {
    return new Promise((resolve, reject) => {
        const socket = tcp.connect({ host: '127.0.0.1', port: port });
        const chunks = [];
        const timer = setTimeout(() => {
            socket.destroy();
            reject(new Error('tcpQuery timeout'));
        }, 1500);
        timer.unref?.();
        socket.on('data', (chunk) => chunks.push(chunk));
        socket.once('end', () => {
            clearTimeout(timer);
            const all = Buffer.concat(chunks);
            if (all.length < 2) {
                reject(new Error('short response'));
                return;
            }
            const len = all.readUInt16BE(0);
            resolve(Packet.parse(all.subarray(2, 2 + len)));
        });
        socket.once('error', (err) => {
            clearTimeout(timer);
            reject(err);
        });
        socket.write(frame(payload));
    });
};
const tlsQuery = (port, payload) => {
    return new Promise((resolve, reject) => {
        const socket = tls.connect({ host: '127.0.0.1', port: port, rejectUnauthorized: false });
        const chunks = [];
        const timer = setTimeout(() => {
            socket.destroy();
            reject(new Error('tlsQuery timeout'));
        }, 2000);
        timer.unref?.();
        socket.on('data', (chunk) => chunks.push(chunk));
        socket.once('end', () => {
            clearTimeout(timer);
            const all = Buffer.concat(chunks);
            if (all.length < 2) {
                reject(new Error('short response'));
                return;
            }
            const len = all.readUInt16BE(0);
            resolve(Packet.parse(all.subarray(2, 2 + len)));
        });
        socket.once('error', (err) => {
            clearTimeout(timer);
            reject(err);
        });
        socket.write(frame(payload));
    });
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
const startTcpServer = async (cookies) => {
    const server = new TCPServer({ tcp: { cookies: cookies } });
    const received = [];
    const rejected = [];
    server.on('request', (msg, send) => {
        received.push(msg);
        const reply = new Packet();
        reply.header.id = msg.header.id;
        reply.header.qr = 1;
        reply.header.rd = msg.header.rd;
        reply.questions = msg.questions.slice();
        reply.answers = [new PacketResource(msg.questions[0].name, new A('203.0.113.5'), PacketClass.IN, 60)];
        send(reply);
    });
    server.on('cookieRejected', (_msg, _client, reason) => {
        rejected.push(reason);
    });
    await new Promise((resolve) => {
        server.listen({ port: 0, host: '127.0.0.1' });
        server.once('listening', () => resolve());
    });
    const addr = server.address();
    return { server: server, port: addr.port, received: received, rejected: rejected };
};
const stopTcp = (handle) => {
    return new Promise((resolve) => handle.server.close(() => resolve()));
};
test('TCPServer cookies: lenient no-cookie query passes through', async () => {
    const handle = await startTcpServer({ secret: SECRET });
    try {
        const resp = await tcpQuery(handle.port, buildQuery(0x1234, 'host.test'));
        assert.equal(resp.header.rcode, 0);
        assert.equal(resp.answers.length, 1);
        assert.equal(handle.received.length, 1);
        assert.equal(handle.rejected.length, 0);
    }
    finally {
        await stopTcp(handle);
    }
});
test('TCPServer cookies: client-only cookie gets BADCOOKIE with fresh server cookie', async () => {
    const handle = await startTcpServer({ secret: SECRET });
    try {
        const clientCookie = EdnsCookie.generateClientCookie();
        const resp = await tcpQuery(handle.port, buildQuery(1, 'host.test', new EdnsCookie(clientCookie)));
        assert.equal(resp.header.rcode, 7, 'BADCOOKIE low nibble');
        assert.equal(handle.received.length, 0);
        assert.deepEqual(handle.rejected, ['no-server-cookie']);
        const cookie = findCookieOption(resp);
        assert.ok(cookie !== null);
        assert.ok(cookie.serverCookie !== null);
        assert.deepEqual(Array.from(cookie.clientCookie), Array.from(clientCookie));
        const opt = resp.additionals.find((r) => r.packetType.type === PacketTypes.EDNS);
        assert.equal((opt.ttl >>> 24) & 0xFF, 1, 'extended rcode upper byte');
    }
    finally {
        await stopTcp(handle);
    }
});
test('TCPServer cookies: valid server cookie reaches handler and response auto-refreshes', async () => {
    const handle = await startTcpServer({ secret: SECRET });
    try {
        const clientCookie = EdnsCookie.generateClientCookie();
        const validServer = EdnsCookie.computeServerCookie(clientCookie, Buffer.from([127, 0, 0, 1]), SECRET);
        const resp = await tcpQuery(handle.port, buildQuery(2, 'host.test', new EdnsCookie(clientCookie, validServer)));
        assert.equal(resp.header.rcode, 0);
        assert.equal(handle.received.length, 1);
        assert.equal(resp.answers.length, 1);
        const cookie = findCookieOption(resp);
        assert.ok(cookie !== null);
        assert.ok(cookie.serverCookie !== null);
        assert.ok(EdnsCookie.verifyServerCookie(cookie.serverCookie, cookie.clientCookie, Buffer.from([127, 0, 0, 1]), SECRET));
    }
    finally {
        await stopTcp(handle);
    }
});
test('TCPServer cookies: tampered server cookie gets BADCOOKIE', async () => {
    const handle = await startTcpServer({ secret: SECRET });
    try {
        const clientCookie = EdnsCookie.generateClientCookie();
        const valid = EdnsCookie.computeServerCookie(clientCookie, Buffer.from([127, 0, 0, 1]), SECRET);
        const tampered = Buffer.from(valid);
        tampered[12] ^= 0x01;
        const resp = await tcpQuery(handle.port, buildQuery(3, 'host.test', new EdnsCookie(clientCookie, tampered)));
        assert.equal(resp.header.rcode, 7);
        assert.equal(handle.received.length, 0);
        assert.deepEqual(handle.rejected, ['invalid-cookie']);
    }
    finally {
        await stopTcp(handle);
    }
});
test('TCPServer cookies: strict mode REFUSES queries without cookie option', async () => {
    const handle = await startTcpServer({ secret: SECRET, mode: 'strict' });
    try {
        const resp = await tcpQuery(handle.port, buildQuery(4, 'host.test'));
        assert.equal(resp.header.rcode, 5);
        assert.equal(handle.received.length, 0);
        assert.deepEqual(handle.rejected, ['no-cookie-strict']);
    }
    finally {
        await stopTcp(handle);
    }
});
test('TCPServer cookies: strict mode still accepts valid-cookie queries', async () => {
    const handle = await startTcpServer({ secret: SECRET, mode: 'strict' });
    try {
        const clientCookie = EdnsCookie.generateClientCookie();
        const valid = EdnsCookie.computeServerCookie(clientCookie, Buffer.from([127, 0, 0, 1]), SECRET);
        const resp = await tcpQuery(handle.port, buildQuery(5, 'host.test', new EdnsCookie(clientCookie, valid)));
        assert.equal(resp.header.rcode, 0);
        assert.equal(handle.received.length, 1);
    }
    finally {
        await stopTcp(handle);
    }
});
test('TLSServer cookies: end-to-end DoT BADCOOKIE + retry path', async () => {
    const received = [];
    const rejected = [];
    const server = new TLSServer({
        tls: {
            options: { cert: tlsCert, key: tlsKey },
            cookies: { secret: SECRET }
        }
    });
    server.on('request', (msg, send) => {
        received.push(msg);
        const reply = new Packet();
        reply.header.id = msg.header.id;
        reply.header.qr = 1;
        reply.header.rd = msg.header.rd;
        reply.questions = msg.questions.slice();
        reply.answers = [new PacketResource(msg.questions[0].name, new A('203.0.113.55'), PacketClass.IN, 60)];
        send(reply);
    });
    server.on('cookieRejected', (_msg, _client, reason) => {
        rejected.push(reason);
    });
    await new Promise((resolve) => {
        server.listen({ port: 0, host: '127.0.0.1' });
        server.once('listening', () => resolve());
    });
    const addr = server.address();
    try {
        const clientCookie = EdnsCookie.generateClientCookie();
        const reject = await tlsQuery(addr.port, buildQuery(10, 'host.test', new EdnsCookie(clientCookie)));
        assert.equal(reject.header.rcode, 7);
        assert.deepEqual(rejected, ['no-server-cookie']);
        const issued = findCookieOption(reject);
        assert.ok(issued !== null);
        assert.ok(issued.serverCookie !== null);
        const accept = await tlsQuery(addr.port, buildQuery(11, 'host.test', new EdnsCookie(clientCookie, issued.serverCookie)));
        assert.equal(accept.header.rcode, 0);
        assert.equal(received.length, 1);
    }
    finally {
        await new Promise((resolve) => server.close(() => resolve()));
    }
});
test('TCPClient cookies: first query gets BADCOOKIE then retries with learned cookie', async () => {
    const handle = await startTcpServer({ secret: SECRET });
    try {
        const jar = new ClientCookieJar();
        const resolve = TCPClient.request({
            dns: '127.0.0.1',
            port: handle.port,
            cookies: jar
        });
        const resp = await resolve('host.test', PacketTypes.A, PacketClass.IN);
        assert.equal(resp.header.rcode, 0);
        assert.equal(resp.answers.length, 1);
        assert.equal(handle.received.length, 1, 'only the retry reached the handler');
        assert.deepEqual(handle.rejected, ['no-server-cookie']);
        const entry = jar.peek('127.0.0.1', handle.port);
        assert.ok(entry !== null);
        assert.ok(entry.serverCookie !== null);
    }
    finally {
        await stopTcp(handle);
    }
});
test('TCPClient cookies: second query reuses jar — no BADCOOKIE round-trip', async () => {
    const handle = await startTcpServer({ secret: SECRET });
    try {
        const jar = new ClientCookieJar();
        const resolve = TCPClient.request({
            dns: '127.0.0.1',
            port: handle.port,
            cookies: jar
        });
        await resolve('host.test', PacketTypes.A, PacketClass.IN);
        const rejectedAfterFirst = handle.rejected.length;
        const seenAfterFirst = handle.received.length;
        await resolve('host2.test', PacketTypes.A, PacketClass.IN);
        assert.equal(handle.rejected.length, rejectedAfterFirst);
        assert.equal(handle.received.length, seenAfterFirst + 1);
    }
    finally {
        await stopTcp(handle);
    }
});
test('TCPClient cookies: shared jar with UDPClient reuses same cookie pair (cross-transport)', async () => {
    const handle = await startTcpServer({ secret: SECRET });
    try {
        const jar = new ClientCookieJar();
        const resolveTcp = TCPClient.request({
            dns: '127.0.0.1',
            port: handle.port,
            cookies: jar
        });
        await resolveTcp('host.test', PacketTypes.A, PacketClass.IN);
        const tcpEntry = jar.peek('127.0.0.1', handle.port);
        assert.ok(tcpEntry !== null);
        assert.ok(tcpEntry.serverCookie !== null);
        const rejectedBefore = handle.rejected.length;
        await resolveTcp('host2.test', PacketTypes.A, PacketClass.IN);
        assert.equal(handle.rejected.length, rejectedBefore);
        const tcpEntry2 = jar.peek('127.0.0.1', handle.port);
        assert.deepEqual(tcpEntry2.clientCookie, tcpEntry.clientCookie);
    }
    finally {
        await stopTcp(handle);
    }
});
test('TCPClient cookies: works over DoT (TLS transport)', async () => {
    const received = [];
    const rejected = [];
    const server = new TLSServer({
        tls: {
            options: { cert: tlsCert, key: tlsKey },
            cookies: { secret: SECRET }
        }
    });
    server.on('request', (msg, send) => {
        received.push(msg);
        const reply = new Packet();
        reply.header.id = msg.header.id;
        reply.header.qr = 1;
        reply.header.rd = msg.header.rd;
        reply.questions = msg.questions.slice();
        reply.answers = [new PacketResource(msg.questions[0].name, new A('203.0.113.99'), PacketClass.IN, 60)];
        send(reply);
    });
    server.on('cookieRejected', (_msg, _client, reason) => rejected.push(reason));
    await new Promise((resolve) => {
        server.listen({ port: 0, host: '127.0.0.1' });
        server.once('listening', () => resolve());
    });
    const addr = server.address();
    try {
        const prev = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        try {
            const jar = new ClientCookieJar();
            const resolve = TCPClient.request({
                dns: '127.0.0.1',
                port: addr.port,
                protocol: ClientOptionsProtocol.tls,
                cookies: jar
            });
            const resp = await resolve('host.test', PacketTypes.A, PacketClass.IN);
            assert.equal(resp.header.rcode, 0);
            assert.equal(received.length, 1);
            assert.deepEqual(rejected, ['no-server-cookie']);
        }
        finally {
            if (prev === undefined) {
                delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
            }
            else {
                process.env.NODE_TLS_REJECT_UNAUTHORIZED = prev;
            }
        }
    }
    finally {
        await new Promise((resolve) => server.close(() => resolve()));
    }
});
//# sourceMappingURL=tcpCookies.js.map