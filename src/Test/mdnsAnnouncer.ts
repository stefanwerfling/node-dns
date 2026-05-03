import assert from 'assert';
import dgram from 'dgram';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {A} from '../Packet/Types/A.js';
import {MdnsAnnouncer} from '../Server/MdnsAnnouncer.js';
import {MdnsServer} from '../Server/MdnsServer.js';
import {test} from './test.js';

const aRec = (name: string, addr: string, ttl: number = 120): PacketResource =>
    new PacketResource(name, new A(addr), PacketClass.IN, ttl);

/**
 * Bind an observer dgram socket on the same port the server is
 * announcing to. Tests use `port: 0` + `multicastAddr: 127.0.0.1`,
 * so the observer needs to know the actual bound port and
 * `reuseAddr: true` to share the socket.
 */
const observeAnnouncements = async(serverPort: number): Promise<{
    socket: dgram.Socket;
    received: Packet[];
}> => {
    const socket = dgram.createSocket({type: 'udp4', reuseAddr: true});
    const received: Packet[] = [];

    socket.on('message', (msg) => {
        try {
            received.push(Packet.parse(msg));
        } catch {
            /* ignore */
        }
    });

    await new Promise<void>((r) => socket.bind(serverPort, '127.0.0.1', () => r()));
    return {socket: socket, received: received};
};

const closeSocket = (socket: dgram.Socket): Promise<void> => new Promise((r) => {
    try {
        socket.close(() => r());
    } catch {
        r();
    }
});

const buildServer = async(): Promise<MdnsServer> => {
    const server = new MdnsServer({
        multicastAddr: '127.0.0.1',
        port: 0,
        interfaceAddress: '127.0.0.1'
    });
    await server.listen();
    return server;
};

/* schedule ------------------------------------------------------------- */

test('MdnsAnnouncer follows the configured schedule', async() => {
    const server = await buildServer();
    const port = server.address().port;
    const observer = await observeAnnouncements(port);

    const records = [aRec('host.local', '10.0.0.1')];

    const announcer = new MdnsAnnouncer(server, records, {
        schedule: [20, 20, 20],
        goodbyeOnStop: false
    }).start();

    try {
        // Three ticks at 20ms each → ~60ms total, give some headroom.
        await new Promise((r) => setTimeout(r, 120));

        const announcements = observer.received.filter(
            (p) => p.header.qr === 1 && p.answers.length > 0 && p.answers[0].ttl > 0
        );
        assert.strictEqual(announcements.length, 3, 'one announcement per schedule entry');
    } finally {
        await announcer.stop();
        await closeSocket(observer.socket);
        server.close();
    }
});

test('MdnsAnnouncer with empty schedule + steadyState only fires periodic ticks', async() => {
    const server = await buildServer();
    const port = server.address().port;
    const observer = await observeAnnouncements(port);

    const records = [aRec('host.local', '10.0.0.1')];

    const announcer = new MdnsAnnouncer(server, records, {
        schedule: [],
        steadyStateMs: 25,
        goodbyeOnStop: false
    }).start();

    try {
        await new Promise((r) => setTimeout(r, 120));

        const announcements = observer.received.filter(
            (p) => p.header.qr === 1 && p.answers.length > 0 && p.answers[0].ttl > 0
        );
        // Expect ~4 ticks in 100ms at 25ms intervals — allow some slack.
        assert.ok(announcements.length >= 3, `expected ≥3 steady-state ticks, got ${announcements.length}`);
    } finally {
        await announcer.stop();
        await closeSocket(observer.socket);
        server.close();
    }
});

test('MdnsAnnouncer.stop sends goodbye when goodbyeOnStop is true (default)', async() => {
    const server = await buildServer();
    const port = server.address().port;
    const observer = await observeAnnouncements(port);

    const records = [aRec('host.local', '10.0.0.1')];

    const announcer = new MdnsAnnouncer(server, records, {
        schedule: [50],
    }).start();

    try {
        await new Promise((r) => setTimeout(r, 20));   // before any tick fires
        await announcer.stop();
        await new Promise((r) => setTimeout(r, 30));   // let goodbye reach observer

        const goodbyes = observer.received.filter(
            (p) => p.header.qr === 1 && p.answers.length > 0 && p.answers[0].ttl === 0
        );
        assert.strictEqual(goodbyes.length, 1, 'stop() should emit a TTL=0 announcement');
    } finally {
        await closeSocket(observer.socket);
        server.close();
    }
});

test('MdnsAnnouncer.stop with goodbyeOnStop:false skips the goodbye', async() => {
    const server = await buildServer();
    const port = server.address().port;
    const observer = await observeAnnouncements(port);

    const records = [aRec('host.local', '10.0.0.1')];

    const announcer = new MdnsAnnouncer(server, records, {
        schedule: [50],
        goodbyeOnStop: false
    }).start();

    try {
        await announcer.stop();
        await new Promise((r) => setTimeout(r, 30));

        const goodbyes = observer.received.filter(
            (p) => p.header.qr === 1 && p.answers.length > 0 && p.answers[0].ttl === 0
        );
        assert.strictEqual(goodbyes.length, 0, 'goodbyeOnStop:false suppresses TTL=0 emit');
    } finally {
        await closeSocket(observer.socket);
        server.close();
    }
});

test('MdnsAnnouncer.start is idempotent', async() => {
    const server = await buildServer();
    const port = server.address().port;
    const observer = await observeAnnouncements(port);

    const records = [aRec('host.local', '10.0.0.1')];

    const announcer = new MdnsAnnouncer(server, records, {
        schedule: [25, 25],
        goodbyeOnStop: false
    });
    announcer.start();
    announcer.start();   // second start must not duplicate the schedule
    announcer.start();

    try {
        await new Promise((r) => setTimeout(r, 80));

        const announcements = observer.received.filter(
            (p) => p.header.qr === 1 && p.answers.length > 0 && p.answers[0].ttl > 0
        );
        assert.strictEqual(announcements.length, 2, 'duplicate start() calls must be no-ops');
    } finally {
        await announcer.stop();
        await closeSocket(observer.socket);
        server.close();
    }
});

test('MdnsAnnouncer.stop is idempotent', async() => {
    const server = await buildServer();
    const records = [aRec('host.local', '10.0.0.1')];

    const announcer = new MdnsAnnouncer(server, records, {
        schedule: [25],
        goodbyeOnStop: false
    }).start();

    try {
        await announcer.stop();
        await announcer.stop();   // second stop is a no-op, must not throw
    } finally {
        server.close();
    }
});

test('MdnsAnnouncer.initialAnnounce fires one announcement before the schedule', async() => {
    const server = await buildServer();
    const port = server.address().port;
    const observer = await observeAnnouncements(port);

    const records = [aRec('host.local', '10.0.0.1')];

    const announcer = new MdnsAnnouncer(server, records, {
        schedule: [50],            // first scheduled tick at 50ms
        initialAnnounce: true,
        goodbyeOnStop: false
    }).start();

    try {
        // Wait less than the first schedule entry — should already
        // have the initialAnnounce on the wire.
        await new Promise((r) => setTimeout(r, 20));

        const announcements = observer.received.filter(
            (p) => p.header.qr === 1 && p.answers.length > 0 && p.answers[0].ttl > 0
        );
        assert.strictEqual(announcements.length, 1, 'initialAnnounce fires immediately');
    } finally {
        await announcer.stop();
        await closeSocket(observer.socket);
        server.close();
    }
});

test('MdnsAnnouncer with empty record list is a no-op', async() => {
    const server = await buildServer();
    const port = server.address().port;
    const observer = await observeAnnouncements(port);

    const announcer = new MdnsAnnouncer(server, [], {
        schedule: [20],
        initialAnnounce: true
    }).start();

    try {
        await new Promise((r) => setTimeout(r, 60));

        const announcements = observer.received.filter(
            (p) => p.header.qr === 1 && p.answers.length > 0
        );
        assert.strictEqual(announcements.length, 0, 'no records → no announcements');
    } finally {
        await announcer.stop();
        await closeSocket(observer.socket);
        server.close();
    }
});

test('MdnsAnnouncer reports send errors via on("error") instead of crashing', async() => {
    const server = await buildServer();
    server.close();   // tear down BEFORE the announcer ticks → send must fail

    const records = [aRec('host.local', '10.0.0.1')];
    const errors: Error[] = [];

    const announcer = new MdnsAnnouncer(server, records, {
        schedule: [20, 20],
        goodbyeOnStop: false
    });

    announcer.on('error', (err) => errors.push(err));
    announcer.start();

    try {
        await new Promise((r) => setTimeout(r, 80));

        // The schedule should still tick; each tick raises an error
        // through the listener but doesn't break the loop.
        assert.ok(errors.length >= 1, 'send failures must surface via on("error")');
    } finally {
        await announcer.stop();
    }
});

test('MdnsAnnouncer.running reflects lifecycle state', async() => {
    const server = await buildServer();
    const records = [aRec('host.local', '10.0.0.1')];

    const announcer = new MdnsAnnouncer(server, records, {
        schedule: [],
        steadyStateMs: 0,         // schedule exhaustion → quiet stop
        goodbyeOnStop: false
    });

    assert.strictEqual(announcer.running, false, 'false before start');

    announcer.start();

    // Schedule exhausted on first scheduleNext() call (empty schedule
    // + 0 steady-state) — running flips back to false synchronously.
    assert.strictEqual(announcer.running, false, 'false after schedule completes without steady-state');

    server.close();
});