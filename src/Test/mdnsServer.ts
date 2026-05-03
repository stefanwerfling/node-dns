import assert from 'assert';
import dgram from 'dgram';
import {MdnsClient} from '../Client/MdnsClient.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {MdnsServer} from '../Server/MdnsServer.js';
import {test} from './test.js';

const aRec = (name: string, addr: string): PacketResource =>
    new PacketResource(name, new A(addr), PacketClass.IN, 120);

test('MdnsServer#fires request and the handler can reply unicast', async() => {
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
        // Force unicast so the test client (on a different port) receives it.
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
        assert.equal((responses[0].answers[0].packetType as A).address, '192.168.1.5');
    } finally {
        server.close();
    }
});

test('MdnsServer#filters out responses (qr=1) — only queries fire request', async() => {
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

    // Send a fabricated *response* (qr=1) directly to the server. It
    // must be ignored.
    const sender = dgram.createSocket('udp4');
    await new Promise<void>((r) => sender.bind(0, '127.0.0.1', () => r()));

    const fake = new Packet();
    fake.header.qr = 1;   // response, not query
    fake.header.aa = 1;
    fake.answers = [aRec('printer.local', '10.0.0.1')];
    sender.send(fake.toBuffer(), port, '127.0.0.1');

    // Then send a real query. Should fire request.
    const realQuery = new Packet();
    realQuery.header.qr = 0;
    realQuery.questions = [new PacketQuestion('printer.local', PacketTypes.A, PacketClass.IN)];
    sender.send(realQuery.toBuffer(), port, '127.0.0.1');

    // Wait for both messages to be processed.
    await new Promise((resolve) => setTimeout(resolve, 100));

    assert.equal(requestCount, 1, 'qr=1 must be filtered, qr=0 must fire');

    sender.close();
    server.close();
});

test('MdnsServer#malformed datagram triggers requestError, not request', async() => {
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
    await new Promise<void>((r) => sender.bind(0, '127.0.0.1', () => r()));

    sender.send(Buffer.from([0xff, 0xff, 0xff, 0xff]), port, '127.0.0.1');
    await new Promise((resolve) => setTimeout(resolve, 50));

    assert.equal(requestCount, 0);
    assert.equal(errorCount, 1);

    sender.close();
    server.close();
});

test('MdnsServer#auto target uses unicast when QU bit is set on the question', async() => {
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
        // Default 'auto' — should pick unicast because the question
        // had the QU bit set (unicastResponse: true on the client).
        void send(reply);
    });

    await server.listen();
    const port = server.address().port;

    try {
        const resolve = MdnsClient.request({
            multicastAddr: '127.0.0.1',
            port: port,
            timeoutMs: 200,
            unicastResponse: true       // sets the QU bit
        });

        const responses = await resolve('printer.local', PacketTypes.A);
        // The client's source port differs from the server's bound
        // port, so receiving a response at all confirms unicast.
        assert.equal(responses.length, 1);
        assert.equal((responses[0].answers[0].packetType as A).address, '192.168.1.5');
    } finally {
        server.close();
    }
});

test('MdnsServer#address() returns the bound port + address', async() => {
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
    } finally {
        server.close();
    }
});

test('MdnsServer#rawRequest matches the wire bytes (TSIG-friendly)', async() => {
    const server = new MdnsServer({
        multicastAddr: '127.0.0.1',
        port: 0,
        interfaceAddress: '127.0.0.1'
    });

    let observed: Buffer | null = null;
    server.on('request', (_msg, _send, _rinfo, raw) => {
        observed = raw;
    });

    await server.listen();
    const port = server.address().port;

    const sender = dgram.createSocket('udp4');
    await new Promise<void>((r) => sender.bind(0, '127.0.0.1', () => r()));

    const query = new Packet();
    query.header.qr = 0;
    query.questions = [new PacketQuestion('tv.local', PacketTypes.A, PacketClass.IN)];
    const wire = query.toBuffer();
    sender.send(wire, port, '127.0.0.1');

    await new Promise((resolve) => setTimeout(resolve, 50));

    assert.ok(observed);
    assert.deepEqual(observed!, wire,
        'rawRequest must equal the bytes that arrived on the wire');

    sender.close();
    server.close();
});

/* announce + goodbye --------------------------------------------------- */

test('MdnsServer#announce multicasts a NOERROR response with cache-flush bit set', async() => {
    const server = new MdnsServer({
        multicastAddr: '127.0.0.1',
        port: 0,
        interfaceAddress: '127.0.0.1'
    });

    await server.listen();
    const port = server.address().port;

    // Listener that catches the multicast destination — same trick as
    // the existing tests: 127.0.0.1 isn't real multicast, so a vanilla
    // UDP socket on the same port + addr receives directly.
    const observer = dgram.createSocket({type: 'udp4', reuseAddr: true});
    const observed: Packet[] = [];

    observer.on('message', (msg) => {
        try {
            observed.push(Packet.parse(msg));
        } catch {
            /* ignore */
        }
    });

    await new Promise<void>((r) => observer.bind(port, '127.0.0.1', () => r()));

    try {
        await server.announce([aRec('host.local', '10.0.0.1')]);
        await new Promise((r) => setTimeout(r, 50));

        assert.strictEqual(observed.length, 1);
        const pkt = observed[0];
        assert.strictEqual(pkt.header.qr, 1, 'announcement is a response');
        assert.strictEqual(pkt.header.aa, 1, 'authoritative');
        assert.strictEqual(pkt.questions.length, 0, 'unsolicited — no question section');
        assert.strictEqual(pkt.answers.length, 1);
        // eslint-disable-next-line no-bitwise
        assert.notStrictEqual(pkt.answers[0].class & 0x8000, 0, 'cache-flush bit set');
        assert.strictEqual(pkt.answers[0].ttl, 120, 'TTL preserved on announcement');
    } finally {
        observer.close();
        server.close();
    }
});

test('MdnsServer#goodbye stamps TTL=0 on every record (RFC 6762 §10.1)', async() => {
    const server = new MdnsServer({
        multicastAddr: '127.0.0.1',
        port: 0,
        interfaceAddress: '127.0.0.1'
    });

    await server.listen();
    const port = server.address().port;

    const observer = dgram.createSocket({type: 'udp4', reuseAddr: true});
    const observed: Packet[] = [];

    observer.on('message', (msg) => {
        try {
            observed.push(Packet.parse(msg));
        } catch {
            /* ignore */
        }
    });

    await new Promise<void>((r) => observer.bind(port, '127.0.0.1', () => r()));

    try {
        await server.goodbye([
            aRec('host.local', '10.0.0.1'),
            aRec('host.local', '10.0.0.2')
        ]);
        await new Promise((r) => setTimeout(r, 50));

        assert.strictEqual(observed.length, 1);
        const pkt = observed[0];
        assert.strictEqual(pkt.answers.length, 2);

        for (const r of pkt.answers) {
            assert.strictEqual(r.ttl, 0, 'goodbye TTL must be zero');
            // eslint-disable-next-line no-bitwise
            assert.notStrictEqual(r.class & 0x8000, 0, 'cache-flush bit set on goodbye too');
        }
    } finally {
        observer.close();
        server.close();
    }
});

test('MdnsServer#announce does not mutate caller-supplied records', async() => {
    const server = new MdnsServer({
        multicastAddr: '127.0.0.1',
        port: 0,
        interfaceAddress: '127.0.0.1'
    });

    await server.listen();

    try {
        const original = aRec('host.local', '10.0.0.1');
        const beforeClass = original.class;
        const beforeTtl = original.ttl;

        await server.goodbye([original]);

        assert.strictEqual(original.class, beforeClass, 'caller class must be untouched');
        assert.strictEqual(original.ttl, beforeTtl, 'caller TTL must be untouched');
    } finally {
        server.close();
    }
});

test('MdnsServer#goodbye on empty record list is a no-op', async() => {
    const server = new MdnsServer({
        multicastAddr: '127.0.0.1',
        port: 0,
        interfaceAddress: '127.0.0.1'
    });

    await server.listen();

    try {
        // Should resolve without throwing or trying to send a packet
        // with zero answers.
        await server.goodbye([]);
        await server.announce([]);
    } finally {
        server.close();
    }
});