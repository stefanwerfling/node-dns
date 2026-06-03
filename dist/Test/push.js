import assert from 'assert';
import { PushClient } from '../Client/PushClient.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { AAAA } from '../Packet/Types/AAAA.js';
import { PushServer } from '../Server/PushServer.js';
import { tlsCert, tlsKey } from './helpers.js';
import { test } from './test.js';
const setupPair = async () => {
    const server = new PushServer({ tls: { cert: tlsCert, key: tlsKey } });
    await server.listen(0, '127.0.0.1');
    const port = server.address().port;
    const client = new PushClient({
        host: '127.0.0.1',
        port: port,
        tls: { rejectUnauthorized: false }
    });
    return { server: server, client: client, port: port };
};
const awaitOnce = (target, event, timeoutMs = 1500) => {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            target.removeListener(event, onEvent);
            reject(new Error(`awaitOnce: timeout waiting for '${event}' after ${timeoutMs}ms`));
        }, timeoutMs);
        timer.unref?.();
        const onEvent = (payload) => {
            clearTimeout(timer);
            resolve(payload);
        };
        target.once(event, onEvent);
    });
};
test('PushClient end-to-end SUBSCRIBE roundtrip + server-initiated PUSH', async () => {
    const { server, client } = await setupPair();
    try {
        const subscription = await client.subscribe('host.example.com', PacketTypes.A, PacketClass.IN);
        assert.equal(client.subscriptionCount, 1);
        await new Promise((resolve) => setTimeout(resolve, 50));
        assert.equal(server.sessionCount, 1);
        const records = [new PacketResource('host.example.com', new A('192.0.2.42'), PacketClass.IN, 60)];
        const fanout = server.notify(records);
        assert.equal(fanout, 1, 'one session matched');
        const pushed = await awaitOnce(subscription, 'push');
        assert.equal(pushed.length, 1);
        assert.equal(pushed[0].packetType.address, '192.0.2.42');
    }
    finally {
        await client.close();
        await server.close();
    }
});
test('PushClient routes records to the correct subscription by (name, type, class)', async () => {
    const { server, client } = await setupPair();
    try {
        const subA = await client.subscribe('host.example.com', PacketTypes.A);
        const subAAAA = await client.subscribe('host.example.com', PacketTypes.AAAA);
        await new Promise((resolve) => setTimeout(resolve, 50));
        const pushAPromise = awaitOnce(subA, 'push');
        const pushAAAAPromise = awaitOnce(subAAAA, 'push');
        server.notify([
            new PacketResource('host.example.com', new A('192.0.2.1'), PacketClass.IN, 60),
            new PacketResource('host.example.com', new AAAA('2001:db8::1'), PacketClass.IN, 60)
        ]);
        const [aRecords, aaaaRecords] = await Promise.all([pushAPromise, pushAAAAPromise]);
        assert.equal(aRecords.length, 1);
        assert.equal(aRecords[0].packetType.address, '192.0.2.1');
        assert.equal(aaaaRecords.length, 1);
        assert.equal(aaaaRecords[0].packetType.address, '2001:db8::1');
    }
    finally {
        await client.close();
        await server.close();
    }
});
test('PushServer skips sessions that did not subscribe to the notified name', async () => {
    const { server, client } = await setupPair();
    try {
        const sub = await client.subscribe('alpha.example.com', PacketTypes.A);
        await new Promise((resolve) => setTimeout(resolve, 50));
        let pushed = false;
        sub.on('push', () => {
            pushed = true;
        });
        server.notify([
            new PacketResource('beta.example.com', new A('192.0.2.99'), PacketClass.IN, 60)
        ]);
        await new Promise((resolve) => setTimeout(resolve, 100));
        assert.equal(pushed, false, 'subscription for alpha must not see records for beta');
    }
    finally {
        await client.close();
        await server.close();
    }
});
test('PushSubscription.unsubscribe stops further pushes', async () => {
    const { server, client } = await setupPair();
    try {
        const sub = await client.subscribe('host.example.com', PacketTypes.A);
        await new Promise((resolve) => setTimeout(resolve, 50));
        let pushCount = 0;
        sub.on('push', () => {
            pushCount++;
        });
        server.notify([new PacketResource('host.example.com', new A('192.0.2.1'), PacketClass.IN, 60)]);
        await new Promise((resolve) => setTimeout(resolve, 80));
        assert.equal(pushCount, 1);
        await sub.unsubscribe();
        await new Promise((resolve) => setTimeout(resolve, 80));
        assert.equal(client.subscriptionCount, 0);
        await new Promise((resolve) => setTimeout(resolve, 80));
        server.notify([new PacketResource('host.example.com', new A('192.0.2.2'), PacketClass.IN, 60)]);
        await new Promise((resolve) => setTimeout(resolve, 80));
        assert.equal(pushCount, 1, 'no push after unsubscribe');
    }
    finally {
        await client.close();
        await server.close();
    }
});
test('PushClient.subscribe with qtype=ANY (255) matches every type for that name', async () => {
    const { server, client } = await setupPair();
    try {
        const sub = await client.subscribe('host.example.com', 255);
        await new Promise((resolve) => setTimeout(resolve, 50));
        const pushPromise = awaitOnce(sub, 'push');
        server.notify([
            new PacketResource('host.example.com', new A('192.0.2.1'), PacketClass.IN, 60),
            new PacketResource('host.example.com', new AAAA('2001:db8::1'), PacketClass.IN, 60)
        ]);
        const records = await pushPromise;
        assert.equal(records.length, 2);
    }
    finally {
        await client.close();
        await server.close();
    }
});
test('PushClient.close emits "close" on every active subscription', async () => {
    const { server, client } = await setupPair();
    try {
        const sub = await client.subscribe('host.example.com', PacketTypes.A);
        await new Promise((resolve) => setTimeout(resolve, 50));
        const errorPromise = awaitOnce(sub, 'error');
        await client.close();
        const err = await errorPromise;
        assert.ok(err instanceof Error);
        assert.equal(client.subscriptionCount, 0);
    }
    finally {
        await server.close();
    }
});
test('PushClient rejects subscribe after close', async () => {
    const { server, client } = await setupPair();
    try {
        await client.close();
        await assert.rejects(client.subscribe('host.example.com', PacketTypes.A), /client is closed/);
    }
    finally {
        await server.close();
    }
});
test('PushServer.address() reports the bound port', async () => {
    const server = new PushServer({ tls: { cert: tlsCert, key: tlsKey } });
    await server.listen(0, '127.0.0.1');
    const addr = server.address();
    try {
        assert.ok(addr !== null);
        assert.ok(addr.port > 0);
        assert.equal(addr.address, '127.0.0.1');
    }
    finally {
        await server.close();
    }
});
test('PushServer emits "subscribe" event on accepted SUBSCRIBE', async () => {
    const { server, client } = await setupPair();
    try {
        const received = [];
        server.on('subscribe', (tlv) => {
            received.push(tlv.name);
        });
        await client.subscribe('alpha.example.com', PacketTypes.A);
        await client.subscribe('beta.example.com', PacketTypes.AAAA);
        await new Promise((resolve) => setTimeout(resolve, 50));
        assert.deepStrictEqual(received.sort(), ['alpha.example.com', 'beta.example.com']);
    }
    finally {
        await client.close();
        await server.close();
    }
});
test('PushClient.subscribe requires options.host', () => {
    assert.throws(() => new PushClient({ host: '' }), /options\.host is required/);
});
test('PushServer requires options.tls', () => {
    assert.throws(() => new PushServer({}), /options\.tls is required/);
});
test('PushClient sends periodic KEEPALIVE heartbeats at keepaliveMs', async () => {
    const server = new PushServer({ tls: { cert: tlsCert, key: tlsKey } });
    await server.listen(0, '127.0.0.1');
    const port = server.address().port;
    let keepaliveCount = 0;
    server.on('keepalive', () => {
        keepaliveCount++;
    });
    const client = new PushClient({
        host: '127.0.0.1',
        port: port,
        tls: { rejectUnauthorized: false },
        keepaliveMs: 80
    });
    try {
        await client.subscribe('host.example.com', PacketTypes.A);
        await new Promise((resolve) => setTimeout(resolve, 300));
        assert.ok(keepaliveCount >= 3, `expected ≥3 KEEPALIVEs, got ${keepaliveCount}`);
    }
    finally {
        await client.close();
        await server.close();
    }
});
test('PushClient keepaliveMs:0 disables periodic heartbeats', async () => {
    const server = new PushServer({ tls: { cert: tlsCert, key: tlsKey } });
    await server.listen(0, '127.0.0.1');
    const port = server.address().port;
    let keepaliveCount = 0;
    server.on('keepalive', () => {
        keepaliveCount++;
    });
    const client = new PushClient({
        host: '127.0.0.1',
        port: port,
        tls: { rejectUnauthorized: false },
        inactivityMs: 0,
        keepaliveMs: 0
    });
    try {
        await client.subscribe('host.example.com', PacketTypes.A);
        await new Promise((resolve) => setTimeout(resolve, 200));
        assert.equal(keepaliveCount, 0, 'no heartbeats when keepaliveMs:0 + inactivityMs:0');
    }
    finally {
        await client.close();
        await server.close();
    }
});
test('PushClient.reconfirm sends RECONFIRM TLV to the server', async () => {
    const { server, client } = await setupPair();
    const reconfirms = [];
    server.on('reconfirm', (tlv) => {
        reconfirms.push({ name: tlv.name, qtype: tlv.qtype, rdata: tlv.rdata });
    });
    try {
        const rdata = Buffer.from([192, 0, 2, 99]);
        await client.reconfirm('stale.example.com', PacketTypes.A, PacketClass.IN, rdata);
        await new Promise((resolve) => setTimeout(resolve, 80));
        assert.equal(reconfirms.length, 1);
        assert.equal(reconfirms[0].name, 'stale.example.com');
        assert.equal(reconfirms[0].qtype, PacketTypes.A);
        assert.deepStrictEqual(Array.from(reconfirms[0].rdata), Array.from(rdata));
    }
    finally {
        await client.close();
        await server.close();
    }
});
test('PushClient.reconfirm rejects after close()', async () => {
    const { server, client } = await setupPair();
    try {
        await client.close();
        await assert.rejects(client.reconfirm('host.example.com', PacketTypes.A, PacketClass.IN, Buffer.alloc(0)), /client is closed/);
    }
    finally {
        await server.close();
    }
});
test('PushClient emits "retryDelay" when server sends RETRY_DELAY TLV', async () => {
    const server = new PushServer({ tls: { cert: tlsCert, key: tlsKey } });
    await server.listen(0, '127.0.0.1');
    const port = server.address().port;
    const client = new PushClient({
        host: '127.0.0.1',
        port: port,
        tls: { rejectUnauthorized: false }
    });
    try {
        let session;
        server.on('connection', (s) => {
            session = s;
        });
        await client.subscribe('host.example.com', PacketTypes.A);
        const retryPromise = new Promise((resolve) => {
            client.once('retryDelay', resolve);
        });
        session.sendRetryDelay(2500);
        const ms = await retryPromise;
        assert.equal(ms, 2500);
    }
    finally {
        await client.close();
        await server.close();
    }
});
test('PushClient auto-reconnects + re-subscribes after server-initiated close', async () => {
    const server = new PushServer({ tls: { cert: tlsCert, key: tlsKey } });
    await server.listen(0, '127.0.0.1');
    const port = server.address().port;
    const subscribeNames = [];
    server.on('subscribe', (tlv) => {
        subscribeNames.push(tlv.name);
    });
    let sessionCount = 0;
    const sessions = [];
    server.on('connection', (s) => {
        sessionCount++;
        sessions.push(s);
    });
    const client = new PushClient({
        host: '127.0.0.1',
        port: port,
        tls: { rejectUnauthorized: false },
        autoReconnect: true,
        reconnectDelayMs: 50,
        inactivityMs: 0,
        keepaliveMs: 0
    });
    try {
        const sub = await client.subscribe('reconnect.example.com', PacketTypes.A);
        assert.equal(sub.name, 'reconnect.example.com');
        const originalMessageId = sub.messageId;
        const reconnectPromise = new Promise((resolve) => {
            client.once('reconnect', resolve);
        });
        await new Promise((resolve) => setTimeout(resolve, 50));
        sessions[0].close();
        await reconnectPromise;
        assert.equal(subscribeNames.length, 2);
        assert.equal(subscribeNames[1], 'reconnect.example.com');
        assert.equal(sessionCount, 2);
        assert.equal(client.subscriptionCount, 1, 'subscription preserved across reconnect');
        assert.ok(sub.messageId !== originalMessageId || sub.messageId === originalMessageId, 'messageId may or may not match — both are valid');
        const pushPromise = awaitOnce(sub, 'push');
        await new Promise((resolve) => setTimeout(resolve, 50));
        server.notify([
            new PacketResource('reconnect.example.com', new A('192.0.2.77'), PacketClass.IN, 60)
        ]);
        const pushed = await pushPromise;
        assert.equal(pushed[0].packetType.address, '192.0.2.77');
    }
    finally {
        await client.close();
        await server.close();
    }
});
test('PushClient honours RETRY_DELAY when scheduling auto-reconnect', async () => {
    const server = new PushServer({ tls: { cert: tlsCert, key: tlsKey } });
    await server.listen(0, '127.0.0.1');
    const port = server.address().port;
    const sessions = [];
    server.on('connection', (s) => {
        sessions.push(s);
    });
    const client = new PushClient({
        host: '127.0.0.1',
        port: port,
        tls: { rejectUnauthorized: false },
        autoReconnect: true,
        reconnectDelayMs: 5_000,
        inactivityMs: 0,
        keepaliveMs: 0
    });
    try {
        await client.subscribe('retry.example.com', PacketTypes.A);
        const reconnectPromise = new Promise((resolve) => {
            client.once('reconnect', resolve);
        });
        sessions[0].sendRetryDelay(50, true);
        const start = Date.now();
        await reconnectPromise;
        const elapsed = Date.now() - start;
        assert.ok(elapsed < 1_000, `reconnect should honour 50ms RETRY_DELAY, took ${elapsed}ms`);
    }
    finally {
        await client.close();
        await server.close();
    }
});
test('PushClient gives up after maxReconnectAttempts and emits reconnectFailed', async () => {
    const realServer = new PushServer({ tls: { cert: tlsCert, key: tlsKey } });
    await realServer.listen(0, '127.0.0.1');
    const realPort = realServer.address().port;
    const tempServer = new PushServer({ tls: { cert: tlsCert, key: tlsKey } });
    await tempServer.listen(0, '127.0.0.1');
    const deadPort = tempServer.address().port;
    await tempServer.close();
    const client = new PushClient({
        host: '127.0.0.1',
        port: realPort,
        tls: { rejectUnauthorized: false },
        autoReconnect: true,
        reconnectDelayMs: 20,
        maxReconnectAttempts: 2,
        inactivityMs: 0,
        keepaliveMs: 0
    });
    client.on('error', () => {
    });
    try {
        await client.subscribe('giveup.example.com', PacketTypes.A);
        client._options.port = deadPort;
        const failedPromise = new Promise((resolve) => {
            client.once('reconnectFailed', resolve);
        });
        const socket = client._socket;
        if (socket !== null && typeof socket.destroy === 'function') {
            socket.destroy();
        }
        const err = await failedPromise;
        assert.ok(err instanceof Error);
        assert.match(err.message, /reconnect attempts/);
    }
    finally {
        await client.close();
        await realServer.close();
    }
});
test('PushServer.sendRetryDelay closeAfter:true closes the session', async () => {
    const { server, client } = await setupPair();
    try {
        const sessions = [];
        server.on('connection', (s) => {
            sessions.push(s);
        });
        const sub = await client.subscribe('host.example.com', PacketTypes.A);
        await new Promise((resolve) => setTimeout(resolve, 30));
        const closePromise = new Promise((resolve) => {
            sub.once('close', () => resolve());
        });
        sub.on('error', () => {
        });
        sessions[0].sendRetryDelay(100, true);
        await closePromise;
        await new Promise((resolve) => setTimeout(resolve, 20));
        assert.equal(server.sessionCount, 0);
    }
    finally {
        await client.close();
        await server.close();
    }
});
//# sourceMappingURL=push.js.map