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
//# sourceMappingURL=push.js.map