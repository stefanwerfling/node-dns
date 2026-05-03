import assert from 'assert';
import dgram from 'dgram';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { A } from '../Packet/Types/A.js';
import { MdnsAnnouncer } from '../Server/MdnsAnnouncer.js';
import { MdnsServer } from '../Server/MdnsServer.js';
import { test } from './test.js';
const aRec = (name, addr, ttl = 120) => new PacketResource(name, new A(addr), PacketClass.IN, ttl);
const observeAnnouncements = async (serverPort) => {
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    const received = [];
    socket.on('message', (msg) => {
        try {
            received.push(Packet.parse(msg));
        }
        catch {
        }
    });
    await new Promise((r) => socket.bind(serverPort, '127.0.0.1', () => r()));
    return { socket: socket, received: received };
};
const closeSocket = (socket) => new Promise((r) => {
    try {
        socket.close(() => r());
    }
    catch {
        r();
    }
});
const buildServer = async () => {
    const server = new MdnsServer({
        multicastAddr: '127.0.0.1',
        port: 0,
        interfaceAddress: '127.0.0.1'
    });
    await server.listen();
    return server;
};
test('MdnsAnnouncer follows the configured schedule', async () => {
    const server = await buildServer();
    const port = server.address().port;
    const observer = await observeAnnouncements(port);
    const records = [aRec('host.local', '10.0.0.1')];
    const announcer = new MdnsAnnouncer(server, records, {
        schedule: [20, 20, 20],
        goodbyeOnStop: false
    }).start();
    try {
        await new Promise((r) => setTimeout(r, 120));
        const announcements = observer.received.filter((p) => p.header.qr === 1 && p.answers.length > 0 && p.answers[0].ttl > 0);
        assert.strictEqual(announcements.length, 3, 'one announcement per schedule entry');
    }
    finally {
        await announcer.stop();
        await closeSocket(observer.socket);
        server.close();
    }
});
test('MdnsAnnouncer with empty schedule + steadyState only fires periodic ticks', async () => {
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
        const announcements = observer.received.filter((p) => p.header.qr === 1 && p.answers.length > 0 && p.answers[0].ttl > 0);
        assert.ok(announcements.length >= 3, `expected ≥3 steady-state ticks, got ${announcements.length}`);
    }
    finally {
        await announcer.stop();
        await closeSocket(observer.socket);
        server.close();
    }
});
test('MdnsAnnouncer.stop sends goodbye when goodbyeOnStop is true (default)', async () => {
    const server = await buildServer();
    const port = server.address().port;
    const observer = await observeAnnouncements(port);
    const records = [aRec('host.local', '10.0.0.1')];
    const announcer = new MdnsAnnouncer(server, records, {
        schedule: [50],
    }).start();
    try {
        await new Promise((r) => setTimeout(r, 20));
        await announcer.stop();
        await new Promise((r) => setTimeout(r, 30));
        const goodbyes = observer.received.filter((p) => p.header.qr === 1 && p.answers.length > 0 && p.answers[0].ttl === 0);
        assert.strictEqual(goodbyes.length, 1, 'stop() should emit a TTL=0 announcement');
    }
    finally {
        await closeSocket(observer.socket);
        server.close();
    }
});
test('MdnsAnnouncer.stop with goodbyeOnStop:false skips the goodbye', async () => {
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
        const goodbyes = observer.received.filter((p) => p.header.qr === 1 && p.answers.length > 0 && p.answers[0].ttl === 0);
        assert.strictEqual(goodbyes.length, 0, 'goodbyeOnStop:false suppresses TTL=0 emit');
    }
    finally {
        await closeSocket(observer.socket);
        server.close();
    }
});
test('MdnsAnnouncer.start is idempotent', async () => {
    const server = await buildServer();
    const port = server.address().port;
    const observer = await observeAnnouncements(port);
    const records = [aRec('host.local', '10.0.0.1')];
    const announcer = new MdnsAnnouncer(server, records, {
        schedule: [25, 25],
        goodbyeOnStop: false
    });
    announcer.start();
    announcer.start();
    announcer.start();
    try {
        await new Promise((r) => setTimeout(r, 80));
        const announcements = observer.received.filter((p) => p.header.qr === 1 && p.answers.length > 0 && p.answers[0].ttl > 0);
        assert.strictEqual(announcements.length, 2, 'duplicate start() calls must be no-ops');
    }
    finally {
        await announcer.stop();
        await closeSocket(observer.socket);
        server.close();
    }
});
test('MdnsAnnouncer.stop is idempotent', async () => {
    const server = await buildServer();
    const records = [aRec('host.local', '10.0.0.1')];
    const announcer = new MdnsAnnouncer(server, records, {
        schedule: [25],
        goodbyeOnStop: false
    }).start();
    try {
        await announcer.stop();
        await announcer.stop();
    }
    finally {
        server.close();
    }
});
test('MdnsAnnouncer.initialAnnounce fires one announcement before the schedule', async () => {
    const server = await buildServer();
    const port = server.address().port;
    const observer = await observeAnnouncements(port);
    const records = [aRec('host.local', '10.0.0.1')];
    const announcer = new MdnsAnnouncer(server, records, {
        schedule: [50],
        initialAnnounce: true,
        goodbyeOnStop: false
    }).start();
    try {
        await new Promise((r) => setTimeout(r, 20));
        const announcements = observer.received.filter((p) => p.header.qr === 1 && p.answers.length > 0 && p.answers[0].ttl > 0);
        assert.strictEqual(announcements.length, 1, 'initialAnnounce fires immediately');
    }
    finally {
        await announcer.stop();
        await closeSocket(observer.socket);
        server.close();
    }
});
test('MdnsAnnouncer with empty record list is a no-op', async () => {
    const server = await buildServer();
    const port = server.address().port;
    const observer = await observeAnnouncements(port);
    const announcer = new MdnsAnnouncer(server, [], {
        schedule: [20],
        initialAnnounce: true
    }).start();
    try {
        await new Promise((r) => setTimeout(r, 60));
        const announcements = observer.received.filter((p) => p.header.qr === 1 && p.answers.length > 0);
        assert.strictEqual(announcements.length, 0, 'no records → no announcements');
    }
    finally {
        await announcer.stop();
        await closeSocket(observer.socket);
        server.close();
    }
});
test('MdnsAnnouncer reports send errors via on("error") instead of crashing', async () => {
    const server = await buildServer();
    server.close();
    const records = [aRec('host.local', '10.0.0.1')];
    const errors = [];
    const announcer = new MdnsAnnouncer(server, records, {
        schedule: [20, 20],
        goodbyeOnStop: false
    });
    announcer.on('error', (err) => errors.push(err));
    announcer.start();
    try {
        await new Promise((r) => setTimeout(r, 80));
        assert.ok(errors.length >= 1, 'send failures must surface via on("error")');
    }
    finally {
        await announcer.stop();
    }
});
test('MdnsAnnouncer.running reflects lifecycle state', async () => {
    const server = await buildServer();
    const records = [aRec('host.local', '10.0.0.1')];
    const announcer = new MdnsAnnouncer(server, records, {
        schedule: [],
        steadyStateMs: 0,
        goodbyeOnStop: false
    });
    assert.strictEqual(announcer.running, false, 'false before start');
    announcer.start();
    assert.strictEqual(announcer.running, false, 'false after schedule completes without steady-state');
    server.close();
});
//# sourceMappingURL=mdnsAnnouncer.js.map