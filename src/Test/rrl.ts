import assert from 'assert';
import dgram from 'dgram';
import {AddressInfo} from 'net';
import {Rrl} from '../Lib/Rrl.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {DnsServer} from '../Server/DnsServer.js';
import {test} from './test.js';

test('rrl#allows up to capacity then drops', () => {
    const rrl = new Rrl({maxRate: 5, capacity: 3, slipRatio: 0});
    const t = 1_000_000;

    assert.equal(rrl.check('192.0.2.1', PacketTypes.A, t), 'allow');
    assert.equal(rrl.check('192.0.2.1', PacketTypes.A, t), 'allow');
    assert.equal(rrl.check('192.0.2.1', PacketTypes.A, t), 'allow');
    assert.equal(rrl.check('192.0.2.1', PacketTypes.A, t), 'drop');
    assert.equal(rrl.check('192.0.2.1', PacketTypes.A, t), 'drop');
});

test('rrl#tokens refill at maxRate per second', () => {
    const rrl = new Rrl({maxRate: 10, capacity: 1, slipRatio: 0});
    const t = 5_000_000;

    assert.equal(rrl.check('10.0.0.1', PacketTypes.A, t), 'allow');
    assert.equal(rrl.check('10.0.0.1', PacketTypes.A, t), 'drop');

    // 100ms later, a single token has refilled (10/s × 0.1s = 1).
    assert.equal(rrl.check('10.0.0.1', PacketTypes.A, t + 100), 'allow');
    assert.equal(rrl.check('10.0.0.1', PacketTypes.A, t + 100), 'drop');
});

test('rrl#slipRatio=2 alternates drop and truncate after exhaustion', () => {
    const rrl = new Rrl({maxRate: 1, capacity: 1, slipRatio: 2});
    const t = 1_000;

    assert.equal(rrl.check('203.0.113.1', PacketTypes.A, t), 'allow');
    assert.equal(rrl.check('203.0.113.1', PacketTypes.A, t), 'drop');
    assert.equal(rrl.check('203.0.113.1', PacketTypes.A, t), 'truncate');
    assert.equal(rrl.check('203.0.113.1', PacketTypes.A, t), 'drop');
    assert.equal(rrl.check('203.0.113.1', PacketTypes.A, t), 'truncate');
});

test('rrl#slipRatio=0 always drops after exhaustion', () => {
    const rrl = new Rrl({maxRate: 1, capacity: 1, slipRatio: 0});
    const t = 0;

    assert.equal(rrl.check('1.1.1.1', PacketTypes.A, t), 'allow');

    for (let i = 0; i < 10; i++) {
        assert.equal(rrl.check('1.1.1.1', PacketTypes.A, t), 'drop');
    }
});

test('rrl#slipRatio=1 always truncates after exhaustion', () => {
    const rrl = new Rrl({maxRate: 1, capacity: 1, slipRatio: 1});
    const t = 0;

    assert.equal(rrl.check('1.1.1.1', PacketTypes.A, t), 'allow');

    for (let i = 0; i < 5; i++) {
        assert.equal(rrl.check('1.1.1.1', PacketTypes.A, t), 'truncate');
    }
});

test('rrl#IPv4 /24 groups distinct hosts into one bucket', () => {
    const rrl = new Rrl({maxRate: 1, capacity: 2, slipRatio: 0, prefixV4Bits: 24});
    const t = 0;

    // Two different /32 hosts, same /24 — share the budget.
    assert.equal(rrl.check('192.0.2.5', PacketTypes.A, t), 'allow');
    assert.equal(rrl.check('192.0.2.99', PacketTypes.A, t), 'allow');
    assert.equal(rrl.check('192.0.2.130', PacketTypes.A, t), 'drop');

    // Different /24 — independent budget.
    assert.equal(rrl.check('192.0.3.1', PacketTypes.A, t), 'allow');
    assert.equal(rrl.check('192.0.3.99', PacketTypes.A, t), 'allow');
    assert.equal(rrl.check('192.0.3.200', PacketTypes.A, t), 'drop');
});

test('rrl#IPv4 /32 makes every host its own bucket', () => {
    const rrl = new Rrl({maxRate: 1, capacity: 1, slipRatio: 0, prefixV4Bits: 32});
    const t = 0;

    assert.equal(rrl.check('192.0.2.5', PacketTypes.A, t), 'allow');
    assert.equal(rrl.check('192.0.2.6', PacketTypes.A, t), 'allow');
    assert.equal(rrl.check('192.0.2.5', PacketTypes.A, t), 'drop');
});

test('rrl#IPv6 /56 groups subnet, /128 splits per host', () => {
    const wide = new Rrl({maxRate: 1, capacity: 1, slipRatio: 0, prefixV6Bits: 56});
    const narrow = new Rrl({maxRate: 1, capacity: 1, slipRatio: 0, prefixV6Bits: 128});
    const t = 0;

    // Two addresses sharing the same /56 prefix.
    assert.equal(wide.check('2001:db8:abcd:1234::1', PacketTypes.A, t), 'allow');
    assert.equal(wide.check('2001:db8:abcd:1234:dead:beef::', PacketTypes.A, t), 'drop');

    assert.equal(narrow.check('2001:db8:abcd:1234::1', PacketTypes.A, t), 'allow');
    assert.equal(narrow.check('2001:db8:abcd:1234:dead:beef::', PacketTypes.A, t), 'allow');
});

test('rrl#different qtypes use separate buckets', () => {
    const rrl = new Rrl({maxRate: 1, capacity: 1, slipRatio: 0});
    const t = 0;

    assert.equal(rrl.check('192.0.2.1', PacketTypes.A, t), 'allow');
    assert.equal(rrl.check('192.0.2.1', PacketTypes.AAAA, t), 'allow');
    assert.equal(rrl.check('192.0.2.1', PacketTypes.MX, t), 'allow');
    assert.equal(rrl.check('192.0.2.1', PacketTypes.A, t), 'drop');
});

test('rrl#maxBuckets caps memory via FIFO eviction', () => {
    const rrl = new Rrl({maxRate: 1, capacity: 1, slipRatio: 0, maxBuckets: 3});

    rrl.check('192.0.2.1', PacketTypes.A, 0);
    rrl.check('192.0.3.1', PacketTypes.A, 0);
    rrl.check('192.0.4.1', PacketTypes.A, 0);
    assert.equal(rrl.size(), 3);

    rrl.check('192.0.5.1', PacketTypes.A, 0);
    assert.equal(rrl.size(), 3);
});

test('rrl#invalid IPv4 / IPv6 input throws', () => {
    const rrl = new Rrl({maxRate: 1});

    assert.throws(() => rrl.check('not.an.address', PacketTypes.A));
    assert.throws(() => rrl.check('192.0.2.999', PacketTypes.A));
    assert.throws(() => rrl.check('2001:db8::g', PacketTypes.A));
    assert.throws(() => rrl.check('2001:db8::1::2', PacketTypes.A));
});

test('rrl#IPv6 with embedded IPv4 tail parses', () => {
    const rrl = new Rrl({maxRate: 1, capacity: 1, slipRatio: 0, prefixV6Bits: 128});

    // ::ffff:1.2.3.4 (IPv4-mapped) parses successfully.
    assert.equal(rrl.check('::ffff:1.2.3.4', PacketTypes.A, 0), 'allow');
    assert.equal(rrl.check('::ffff:1.2.3.4', PacketTypes.A, 0), 'drop');
});

test('rrl#invalid options throw', () => {
    assert.throws(() => new Rrl({maxRate: 0}), /maxRate/u);
    assert.throws(() => new Rrl({maxRate: -1}), /maxRate/u);
    assert.throws(() => new Rrl({maxRate: 5, prefixV4Bits: 33}), /prefixV4Bits/u);
    assert.throws(() => new Rrl({maxRate: 5, prefixV6Bits: 129}), /prefixV6Bits/u);
    assert.throws(() => new Rrl({maxRate: 5, slipRatio: -1}), /slipRatio/u);
});

test('rrl#udp server drops over-budget queries silently', async() => {
    // capacity=1 means the second back-to-back query is rate-limited; with
    // slipRatio=0 the server stays silent so the second client request times out.
    const rrl = new Rrl({maxRate: 1, capacity: 1, slipRatio: 0, prefixV4Bits: 32});

    const observed: Array<'drop'|'truncate'> = [];
    const server = new DnsServer({
        udp: {rrl: rrl},
        handle: (request, send): void => {
            const r = Packet.createResponseFromRequest(request);
            send(r);
        },
    });

    server.on('rateLimited', (_msg, _rinfo, decision) => {
        observed.push(decision);
    });

    const addrs = await server.listen();
    const port = (addrs.udp as AddressInfo).port;

    const sendQuery = (id: number): Promise<Packet|null> => {
        return new Promise<Packet|null>((resolve) => {
            const sock = dgram.createSocket('udp4');
            const query = new Packet();
            query.header.id = id;
            query.questions.push(new PacketQuestion('rrl.test', PacketTypes.A, PacketClass.IN));

            const timer = setTimeout(() => {
                sock.close();
                resolve(null);
            }, 200);

            sock.on('message', (buf) => {
                clearTimeout(timer);
                sock.close();
                resolve(Packet.parse(buf));
            });

            sock.send(query.toBuffer(), port, '127.0.0.1');
        });
    };

    const first = await sendQuery(1);
    const second = await sendQuery(2);

    assert.ok(first);
    assert.equal(first!.header.qr, 1);
    assert.equal(second, null, 'second query should have been silently dropped');
    assert.deepEqual(observed, ['drop']);

    await server.close();
});

test('rrl#udp server slip path returns TC=1 response', async() => {
    // slipRatio=1 → every over-budget query gets a truncated response.
    const rrl = new Rrl({maxRate: 1, capacity: 1, slipRatio: 1, prefixV4Bits: 32});

    const server = new DnsServer({
        udp: {rrl: rrl},
        handle: (request, send): void => {
            send(Packet.createResponseFromRequest(request));
        },
    });

    const addrs = await server.listen();
    const port = (addrs.udp as AddressInfo).port;

    const sendQuery = (id: number): Promise<Packet> => {
        return new Promise<Packet>((resolve, reject) => {
            const sock = dgram.createSocket('udp4');
            const query = new Packet();
            query.header.id = id;
            query.questions.push(new PacketQuestion('rrl.test', PacketTypes.A, PacketClass.IN));

            const timer = setTimeout(() => {
                sock.close();
                reject(new Error('timeout'));
            }, 500);

            sock.on('message', (buf) => {
                clearTimeout(timer);
                sock.close();
                resolve(Packet.parse(buf));
            });

            sock.send(query.toBuffer(), port, '127.0.0.1');
        });
    };

    const first = await sendQuery(0xAA01);
    assert.equal(first.header.qr, 1);
    assert.equal(first.header.tc, 0);
    assert.equal(first.header.id, 0xAA01);

    const second = await sendQuery(0xAA02);
    assert.equal(second.header.qr, 1);
    assert.equal(second.header.tc, 1, 'over-budget query should be marked truncated');
    assert.equal(second.header.id, 0xAA02);
    assert.equal(second.answers.length, 0);
    assert.equal(second.questions.length, 1);

    await server.close();
});