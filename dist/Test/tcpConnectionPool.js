import assert from 'assert';
import tcp from 'net';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { TcpConnectionPool } from '../Client/TcpConnectionPool.js';
import { test } from './test.js';
const startEchoServer = (options = {}) => {
    return new Promise((resolve, reject) => {
        let conns = 0;
        const server = tcp.createServer((socket) => {
            conns++;
            options.onConnection?.(socket);
            let buf = Buffer.alloc(0);
            let expected = null;
            const send = (frame) => {
                const len = Buffer.alloc(2);
                len.writeUInt16BE(frame.length, 0);
                socket.write(Buffer.concat([len, frame]));
            };
            socket.on('data', (chunk) => {
                buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
                while (true) {
                    if (expected === null) {
                        if (buf.length < 2) {
                            return;
                        }
                        expected = buf.readUInt16BE(0);
                        buf = buf.subarray(2);
                    }
                    if (buf.length < expected) {
                        return;
                    }
                    const frame = buf.subarray(0, expected);
                    buf = buf.subarray(expected);
                    expected = null;
                    let query;
                    try {
                        query = Packet.parse(frame);
                    }
                    catch {
                        socket.destroy();
                        return;
                    }
                    const q = query.questions[0];
                    const qname = q?.name ?? '';
                    const ip = options.answerIp ? options.answerIp(qname) : '127.0.0.1';
                    const response = new Packet();
                    response.header.id = query.header.id;
                    response.header.qr = 1;
                    response.header.aa = 1;
                    response.questions = query.questions.slice();
                    response.answers = [
                        new PacketResource(qname, new A(ip), PacketClass.IN, 60)
                    ];
                    const out = response.toBuffer();
                    const delay = options.delayMs ? options.delayMs(qname) : 0;
                    if (delay > 0) {
                        setTimeout(() => {
                            if (!socket.destroyed) {
                                send(out);
                            }
                        }, delay);
                    }
                    else {
                        send(out);
                    }
                }
            });
            socket.on('error', () => {
            });
        });
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => {
            resolve({
                address: () => server.address(),
                connectionCount: () => conns,
                close: () => new Promise((res) => server.close(() => res()))
            });
        });
    });
};
const buildQuery = (name, id = Math.floor(Math.random() * 0xFFFF)) => {
    const p = new Packet();
    p.header.id = id;
    p.header.rd = 1;
    p.questions.push(new PacketQuestion(name, PacketTypes.A, PacketClass.IN));
    return p.toBuffer();
};
test('TcpConnectionPool#single query roundtrip preserves caller ID', async () => {
    const server = await startEchoServer();
    const pool = new TcpConnectionPool();
    try {
        const query = buildQuery('example.com.', 0xCAFE);
        const target = {
            protocol: 'tcp',
            host: '127.0.0.1',
            port: server.address().port
        };
        const reply = await pool.send(target, query);
        const parsed = Packet.parse(reply);
        assert.strictEqual(parsed.header.id, 0xCAFE, 'caller-side ID should be preserved');
        assert.strictEqual(parsed.answers.length, 1);
        assert.strictEqual(parsed.questions[0].name, 'example.com');
    }
    finally {
        pool.close();
        await server.close();
    }
});
test('TcpConnectionPool#reuses single connection across sequential queries', async () => {
    const server = await startEchoServer();
    const pool = new TcpConnectionPool();
    const target = {
        protocol: 'tcp',
        host: '127.0.0.1',
        port: server.address().port
    };
    try {
        for (let i = 0; i < 5; i++) {
            const query = buildQuery(`q${i}.test.`, i);
            const reply = await pool.send(target, query);
            const parsed = Packet.parse(reply);
            assert.strictEqual(parsed.header.id, i);
        }
        assert.strictEqual(server.connectionCount(), 1, 'all five queries should reuse one connection');
        assert.strictEqual(pool.size(), 1);
    }
    finally {
        pool.close();
        await server.close();
    }
});
test('TcpConnectionPool#multiplexes pipelined out-of-order responses by ID', async () => {
    const server = await startEchoServer({
        delayMs: (qname) => qname.startsWith('slow.') ? 30 : 0
    });
    const pool = new TcpConnectionPool();
    const target = {
        protocol: 'tcp',
        host: '127.0.0.1',
        port: server.address().port
    };
    try {
        const slow = pool.send(target, buildQuery('slow.test', 0x0042));
        const fast = pool.send(target, buildQuery('fast.test', 0x0042));
        const order = [];
        const slowDone = slow.then((r) => {
            order.push('slow');
            return r;
        });
        const fastDone = fast.then((r) => {
            order.push('fast');
            return r;
        });
        const [slowReply, fastReply] = await Promise.all([slowDone, fastDone]);
        assert.deepStrictEqual(order, ['fast', 'slow'], 'fast response should arrive first despite slow being sent first');
        const parsedSlow = Packet.parse(slowReply);
        const parsedFast = Packet.parse(fastReply);
        assert.strictEqual(parsedSlow.header.id, 0x0042, 'caller-side ID restored on slow');
        assert.strictEqual(parsedFast.header.id, 0x0042, 'caller-side ID restored on fast');
        assert.strictEqual(parsedSlow.questions[0].name, 'slow.test');
        assert.strictEqual(parsedFast.questions[0].name, 'fast.test');
        assert.strictEqual(server.connectionCount(), 1, 'multiplexed onto single connection');
    }
    finally {
        pool.close();
        await server.close();
    }
});
test('TcpConnectionPool#opens separate connections for distinct targets', async () => {
    const a = await startEchoServer({ answerIp: () => '10.0.0.1' });
    const b = await startEchoServer({ answerIp: () => '10.0.0.2' });
    const pool = new TcpConnectionPool();
    try {
        const targetA = { protocol: 'tcp', host: '127.0.0.1', port: a.address().port };
        const targetB = { protocol: 'tcp', host: '127.0.0.1', port: b.address().port };
        const replyA = Packet.parse(await pool.send(targetA, buildQuery('a.test.', 1)));
        const replyB = Packet.parse(await pool.send(targetB, buildQuery('b.test.', 2)));
        assert.strictEqual(replyA.answers[0].packetType.address, '10.0.0.1');
        assert.strictEqual(replyB.answers[0].packetType.address, '10.0.0.2');
        assert.strictEqual(pool.size(), 2);
        assert.strictEqual(a.connectionCount(), 1);
        assert.strictEqual(b.connectionCount(), 1);
    }
    finally {
        pool.close();
        await a.close();
        await b.close();
    }
});
test('TcpConnectionPool#idle timeout closes connection after inactivity', async () => {
    const server = await startEchoServer();
    const pool = new TcpConnectionPool({ idleTimeoutMs: 50 });
    try {
        const target = { protocol: 'tcp', host: '127.0.0.1', port: server.address().port };
        await pool.send(target, buildQuery('first.test.', 1));
        assert.strictEqual(pool.size(), 1);
        await new Promise((r) => setTimeout(r, 120));
        assert.strictEqual(pool.size(), 0, 'idle connection should be auto-evicted');
        await pool.send(target, buildQuery('second.test.', 2));
        assert.strictEqual(server.connectionCount(), 2, 'second send opened a new socket');
    }
    finally {
        pool.close();
        await server.close();
    }
});
test('TcpConnectionPool#reconnects after peer-closed socket', async () => {
    const server = await startEchoServer();
    const pool = new TcpConnectionPool();
    try {
        const target = { protocol: 'tcp', host: '127.0.0.1', port: server.address().port };
        await pool.send(target, buildQuery('first.test.', 1));
        assert.strictEqual(pool.size(), 1);
        await server.close();
        await new Promise((r) => setTimeout(r, 20));
        assert.strictEqual(pool.size(), 0, 'closed connection should be evicted from pool');
    }
    finally {
        pool.close();
    }
});
test('TcpConnectionPool#query timeout rejects without breaking other queries', async () => {
    const server = await startEchoServer({
        delayMs: (qname) => qname.startsWith('blackhole.') ? 1000 : 0
    });
    const pool = new TcpConnectionPool({ queryTimeoutMs: 30 });
    const target = { protocol: 'tcp', host: '127.0.0.1', port: server.address().port };
    try {
        const stuck = pool.send(target, buildQuery('blackhole.test.', 1));
        const ok = pool.send(target, buildQuery('fine.test.', 2));
        await assert.rejects(stuck, /timeout/);
        const reply = Packet.parse(await ok);
        assert.strictEqual(reply.header.id, 2);
    }
    finally {
        pool.close();
        await server.close();
    }
});
test('TcpConnectionPool#close rejects pending queries', async () => {
    const server = await startEchoServer({
        delayMs: () => 200
    });
    const pool = new TcpConnectionPool();
    const target = { protocol: 'tcp', host: '127.0.0.1', port: server.address().port };
    try {
        const stuck = pool.send(target, buildQuery('slow.test', 1));
        await new Promise((r) => setTimeout(r, 20));
        pool.close();
        await assert.rejects(stuck, /pool closed|connection closed/);
        await assert.rejects(pool.send(target, buildQuery('after.test.', 2)), /pool is closed/);
    }
    finally {
        await server.close();
    }
});
test('TcpConnectionPool#asResolverTransport routes resolver-style calls', async () => {
    const server = await startEchoServer({ answerIp: () => '203.0.113.1' });
    const pool = new TcpConnectionPool();
    try {
        const transport = pool.asResolverTransport();
        const query = new Packet();
        query.header.id = 0x1234;
        query.header.rd = 1;
        query.questions.push(new PacketQuestion('via-transport.test.', PacketTypes.A, PacketClass.IN));
        const reply = await transport('127.0.0.1', server.address().port, query);
        assert.strictEqual(reply.header.id, 0x1234);
        assert.strictEqual(reply.answers[0].packetType.address, '203.0.113.1');
    }
    finally {
        pool.close();
        await server.close();
    }
});
test('TcpConnectionPool#rejects undersized queries before sending', async () => {
    const pool = new TcpConnectionPool();
    try {
        const target = { protocol: 'tcp', host: '127.0.0.1', port: 65535 };
        await assert.rejects(pool.send(target, Buffer.alloc(8)), /too short/);
    }
    finally {
        pool.close();
    }
});
test('TcpConnectionPool#TCPClient honours pool option for end-to-end queries', async () => {
    const { TCPClient } = await import('../Client/TCPClient.js');
    const { ClientOptionsProtocol } = await import('../Client/ClientOptions.js');
    const server = await startEchoServer({ answerIp: () => '198.51.100.7' });
    const pool = new TcpConnectionPool();
    try {
        const resolver = TCPClient.request({
            dns: '127.0.0.1',
            port: server.address().port,
            protocol: ClientOptionsProtocol.tcp,
            pool: pool
        });
        const r1 = await resolver('one.test.', PacketTypes.A, PacketClass.IN);
        const r2 = await resolver('two.test.', PacketTypes.A, PacketClass.IN);
        assert.strictEqual(r1.answers[0].packetType.address, '198.51.100.7');
        assert.strictEqual(r2.answers[0].packetType.address, '198.51.100.7');
        assert.strictEqual(server.connectionCount(), 1, 'TCPClient with pool should reuse the single socket');
    }
    finally {
        pool.close();
        await server.close();
    }
});
//# sourceMappingURL=tcpConnectionPool.js.map