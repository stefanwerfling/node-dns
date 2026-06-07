import assert from 'assert';
import {Buffer} from 'buffer';
import {ClientCookieJar} from '../Client/ClientCookieJar.js';
import {UDPClient} from '../Client/UDPClient.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {EDNS} from '../Packet/Types/EDNS.js';
import {EdnsCookie} from '../Packet/Types/EdnsCookie.js';
import {UDPServer} from '../Server/UDPServer.js';
import {test} from './test.js';

/* helpers ------------------------------------------------------------ */

const SECRET = Buffer.from('client-cookie-test-secret-stable', 'utf8');

type ServerHandle = {
    server: UDPServer;
    port: number;
    seen: Array<{packet: Packet; hadCookie: boolean; hadServerCookie: boolean;}>;
    rejected: string[];
};

const startServer = async(opts: {strict?: boolean;} = {}): Promise<ServerHandle> => {
    const server = new UDPServer({
        udp: {
            cookies: {
                secret: SECRET,
                mode: opts.strict === true ? 'strict' : 'lenient'
            }
        }
    });
    const seen: ServerHandle['seen'] = [];
    const rejected: string[] = [];

    server.on('request', (msg, send) => {
        const cookie = findCookieOption(msg);
        seen.push({
            packet: msg,
            hadCookie: cookie !== null,
            hadServerCookie: cookie !== null && cookie.serverCookie !== null
        });
        const reply = new Packet();
        reply.header.id = msg.header.id;
        reply.header.qr = 1;
        reply.header.rd = msg.header.rd;
        reply.questions = msg.questions.slice();
        reply.answers = [new PacketResource(msg.questions[0].name, new A('203.0.113.7'), PacketClass.IN, 60)];
        send(reply);
    });

    server.on('cookieRejected', (_msg, _rinfo, reason) => {
        rejected.push(reason);
    });

    await server.listen(0, '127.0.0.1');
    return {server: server, port: server.address().port, seen: seen, rejected: rejected};
};

const findCookieOption = (packet: Packet): EdnsCookie | null => {
    for (const r of packet.additionals) {
        if (r.packetType.type !== PacketTypes.EDNS) continue;
        for (const opt of (r.packetType as EDNS).rdata) {
            if (opt instanceof EdnsCookie) return opt;
        }
    }
    return null;
};

const stopServer = (handle: ServerHandle): Promise<void> => {
    return new Promise((resolve) => handle.server.close(() => resolve()));
};

/* tests -------------------------------------------------------------- */

test('ClientCookieJar: getOrCreate allocates stable client cookie per upstream', () => {
    const jar = new ClientCookieJar();
    const a = jar.getOrCreate('1.2.3.4', 53);
    const b = jar.getOrCreate('1.2.3.4', 53);
    const c = jar.getOrCreate('1.2.3.4', 54);

    assert.equal(a, b, 'same upstream returns same entry');
    assert.notEqual(a, c, 'different port returns different entry');
    assert.equal(a.clientCookie.length, 8);
    assert.notDeepEqual(a.clientCookie, c.clientCookie, 'fresh client cookie per endpoint');
    assert.equal(a.serverCookie, null);
});

test('ClientCookieJar: learn / forget / size / clear', () => {
    const jar = new ClientCookieJar();
    jar.getOrCreate('1.1.1.1', 53);
    jar.getOrCreate('9.9.9.9', 53);
    assert.equal(jar.size(), 2);

    const cookie = Buffer.alloc(16, 0xab);
    jar.learn('1.1.1.1', 53, cookie);
    assert.deepEqual(jar.peek('1.1.1.1', 53)!.serverCookie, cookie);

    // null learn is a no-op.
    jar.learn('1.1.1.1', 53, null);
    assert.deepEqual(jar.peek('1.1.1.1', 53)!.serverCookie, cookie);

    jar.forget('1.1.1.1', 53);
    assert.equal(jar.peek('1.1.1.1', 53), null);
    assert.equal(jar.size(), 1);

    jar.clear();
    assert.equal(jar.size(), 0);
});

test('ClientCookieJar: extendedRcode joins header rcode and OPT TTL byte', () => {
    const p = new Packet();
    p.header.rcode = 7;
    // OPT TTL upper byte = 1 → extended rcode 23 (BADCOOKIE).
    // eslint-disable-next-line no-bitwise
    p.additionals.push(new PacketResource('', new EDNS([]), 1232, 1 << 24));

    assert.equal(ClientCookieJar.extendedRcode(p), 23);
    assert.ok(ClientCookieJar.isBadCookie(p));
});

test('ClientCookieJar: isBadCookie is false without OPT or with wrong upper byte', () => {
    const noOpt = new Packet();
    noOpt.header.rcode = 7;
    assert.equal(ClientCookieJar.isBadCookie(noOpt), false);

    const wrongHi = new Packet();
    wrongHi.header.rcode = 7;
    wrongHi.additionals.push(new PacketResource('', new EDNS([]), 1232, 0));
    assert.equal(ClientCookieJar.isBadCookie(wrongHi), false);
});

test('ClientCookieJar: attachTo adds COOKIE option to OPT-less query', () => {
    const jar = new ClientCookieJar();
    const p = new Packet();

    jar.attachTo(p, '1.2.3.4', 53);

    const cookie = ClientCookieJar.findCookieOption(p);
    assert.ok(cookie !== null);
    assert.equal(cookie!.clientCookie.length, 8);
});

test('ClientCookieJar: attachTo preserves other EDNS options', () => {
    const jar = new ClientCookieJar();
    const p = new Packet();
    // Pre-existing OPT with ECS or another option — represented as empty here.
    p.additionals.push(EDNS.createResource([], 4096, false));

    jar.attachTo(p, '1.2.3.4', 53);

    const opt = p.additionals.find((r) => r.packetType.type === PacketTypes.EDNS);
    assert.ok(opt !== undefined);
    // Payload size from caller's OPT preserved.
    assert.equal(opt!.class, 4096);
    assert.equal((opt!.packetType as EDNS).rdata.length, 1);
    assert.ok(ClientCookieJar.findCookieOption(p) !== null);
});

test('ClientCookieJar: attachTo replaces existing COOKIE option (no duplicates)', () => {
    const jar = new ClientCookieJar();
    const p = new Packet();
    p.additionals.push(EDNS.createResource([
        new EdnsCookie(Buffer.alloc(8, 0xff))
    ], 1232, false));

    jar.attachTo(p, '1.2.3.4', 53);

    const opt = p.additionals.find((r) => r.packetType.type === PacketTypes.EDNS);
    const cookies = (opt!.packetType as EDNS).rdata.filter((o) => o instanceof EdnsCookie);
    assert.equal(cookies.length, 1, 'exactly one cookie after attach');

    const jarEntry = jar.peek('1.2.3.4', 53);
    assert.deepEqual((cookies[0] as EdnsCookie).clientCookie, jarEntry!.clientCookie);
});

test('UDPClient cookies: first query gets BADCOOKIE then retries with learned cookie', async() => {
    const handle = await startServer();

    try {
        const jar = new ClientCookieJar();
        const resolve = UDPClient.request({
            dns: '127.0.0.1',
            port: handle.port,
            cookies: jar,
            tcpFallback: false
        });

        const response = await resolve('host.test', PacketTypes.A, PacketClass.IN);
        assert.equal(response.header.rcode, 0);
        assert.equal(response.answers.length, 1);

        // Server saw two queries: first client-only (rejected), then full cookie.
        assert.equal(handle.seen.length, 1, 'only the retry reached the handler');
        assert.equal(handle.seen[0].hadCookie, true);
        assert.equal(handle.seen[0].hadServerCookie, true);
        assert.deepEqual(handle.rejected, ['no-server-cookie']);

        // Jar now holds the learned server cookie for next round.
        const entry = jar.peek('127.0.0.1', handle.port);
        assert.ok(entry !== null);
        assert.ok(entry!.serverCookie !== null);
        assert.ok(entry!.serverCookie!.length >= 8);
    } finally {
        await stopServer(handle);
    }
});

test('UDPClient cookies: second query reuses jar — no BADCOOKIE round-trip', async() => {
    const handle = await startServer();

    try {
        const jar = new ClientCookieJar();
        const resolve = UDPClient.request({
            dns: '127.0.0.1',
            port: handle.port,
            cookies: jar,
            tcpFallback: false
        });

        await resolve('host.test', PacketTypes.A, PacketClass.IN);
        const seenAfterFirst = handle.seen.length;
        const rejectedAfterFirst = handle.rejected.length;

        const response2 = await resolve('host2.test', PacketTypes.A, PacketClass.IN);
        assert.equal(response2.header.rcode, 0);

        // Exactly one new query reached the handler, no new rejection.
        assert.equal(handle.seen.length, seenAfterFirst + 1);
        assert.equal(handle.rejected.length, rejectedAfterFirst);
        assert.equal(handle.seen[handle.seen.length - 1].hadServerCookie, true);
    } finally {
        await stopServer(handle);
    }
});

test('UDPClient cookies: shared jar across two clients skips BADCOOKIE on second client', async() => {
    const handle = await startServer();

    try {
        const jar = new ClientCookieJar();

        const r1 = UDPClient.request({
            dns: '127.0.0.1', port: handle.port, cookies: jar, tcpFallback: false
        });
        await r1('host.test', PacketTypes.A, PacketClass.IN);
        const rejectedAfterPrime = handle.rejected.length;
        const seenAfterPrime = handle.seen.length;

        const r2 = UDPClient.request({
            dns: '127.0.0.1', port: handle.port, cookies: jar, tcpFallback: false
        });
        const response = await r2('host.test', PacketTypes.A, PacketClass.IN);
        assert.equal(response.header.rcode, 0);
        // No BADCOOKIE round-trip; one new query and zero new rejections.
        assert.equal(handle.rejected.length, rejectedAfterPrime);
        assert.equal(handle.seen.length, seenAfterPrime + 1);
    } finally {
        await stopServer(handle);
    }
});

test('UDPClient cookies: cookies:true allocates a private jar — independent of other clients', async() => {
    const handle = await startServer();

    try {
        const r1 = UDPClient.request({
            dns: '127.0.0.1', port: handle.port, cookies: true, tcpFallback: false
        });
        await r1('host.test', PacketTypes.A, PacketClass.IN);
        const rejectedAfterFirst = handle.rejected.length;

        // Independent client → independent jar → expects another BADCOOKIE.
        const r2 = UDPClient.request({
            dns: '127.0.0.1', port: handle.port, cookies: true, tcpFallback: false
        });
        await r2('host.test', PacketTypes.A, PacketClass.IN);

        assert.equal(handle.rejected.length, rejectedAfterFirst + 1);
        assert.deepEqual(handle.rejected.slice(rejectedAfterFirst), ['no-server-cookie']);
    } finally {
        await stopServer(handle);
    }
});

test('UDPClient without cookies option: no cookie sent, server lenient passes', async() => {
    const handle = await startServer();

    try {
        const resolve = UDPClient.request({
            dns: '127.0.0.1',
            port: handle.port,
            tcpFallback: false
        });

        const response = await resolve('host.test', PacketTypes.A, PacketClass.IN);
        assert.equal(response.header.rcode, 0);
        assert.equal(handle.seen.length, 1);
        assert.equal(handle.seen[0].hadCookie, false);
    } finally {
        await stopServer(handle);
    }
});

test('UDPClient cookies: works against strict-mode server (BADCOOKIE then retry)', async() => {
    const handle = await startServer({strict: true});

    try {
        const resolve = UDPClient.request({
            dns: '127.0.0.1',
            port: handle.port,
            cookies: true,
            tcpFallback: false
        });

        const response = await resolve('host.test', PacketTypes.A, PacketClass.IN);
        // Client-only cookie → BADCOOKIE (strict mode still issues fresh
        // cookie because some cookie option was present), then retry with
        // learned server cookie → rcode=0.
        assert.equal(response.header.rcode, 0);
        assert.equal(handle.seen.length, 1);
    } finally {
        await stopServer(handle);
    }
});