import assert from 'assert';
import dgram from 'dgram';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { MdnsProbe } from '../Server/MdnsProbe.js';
import { test } from './test.js';
const aRec = (name, addr) => new PacketResource(name, new A(addr), PacketClass.IN, 120);
const bindPeer = () => {
    return new Promise((resolve, reject) => {
        const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
        const received = [];
        socket.on('error', reject);
        socket.on('message', (msg) => {
            try {
                received.push(Packet.parse(msg));
            }
            catch {
            }
        });
        socket.bind(0, '127.0.0.1', () => {
            const addr = socket.address();
            resolve({ socket: socket, port: addr.port, received: received });
        });
    });
};
const closeSocket = (socket) => new Promise((r) => {
    try {
        socket.close(() => r());
    }
    catch {
        r();
    }
});
test('MdnsProbe#canonicalRecordKey is stable + excludes name + cache-flush bit', () => {
    const a = aRec('one.local', '10.0.0.1');
    const b = aRec('two.local', '10.0.0.1');
    const ka = MdnsProbe.canonicalRecordKey(a);
    const kb = MdnsProbe.canonicalRecordKey(b);
    assert.deepStrictEqual(ka, kb, 'name should not be part of the canonical key');
    const c = new PacketResource('one.local', new A('10.0.0.1'), PacketClass.IN | 0x8000, 120);
    const kc = MdnsProbe.canonicalRecordKey(c);
    assert.deepStrictEqual(kc, ka, 'cache-flush bit must be stripped before comparison');
});
test('MdnsProbe#compareRecordSets — equal sets, we win, we lose, longer set wins on tie', () => {
    const x = [aRec('host.local', '10.0.0.1')];
    const y = [aRec('host.local', '10.0.0.1')];
    assert.strictEqual(MdnsProbe.compareRecordSets(x, y), 0, 'equal sets compare 0');
    const lower = [aRec('host.local', '10.0.0.1')];
    const higher = [aRec('host.local', '10.0.0.2')];
    assert.strictEqual(MdnsProbe.compareRecordSets(higher, lower), 1, 'higher rdata sorts later');
    assert.strictEqual(MdnsProbe.compareRecordSets(lower, higher), -1, 'lower rdata sorts earlier');
    const single = [aRec('host.local', '10.0.0.1')];
    const pair = [aRec('host.local', '10.0.0.1'), aRec('host.local', '10.0.0.2')];
    assert.strictEqual(MdnsProbe.compareRecordSets(pair, single), 1, 'longer set wins on prefix tie');
});
test('MdnsProbe#claim succeeds with no conflicting peer', async () => {
    const peer = await bindPeer();
    try {
        const probeSocket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
        await new Promise((r) => probeSocket.bind(0, '127.0.0.1', () => r()));
        const probeBindPort = probeSocket.address().port;
        await closeSocket(probeSocket);
        const result = await MdnsProbe.claim({
            records: [aRec('host.local', '10.0.0.1')],
            multicastAddr: '127.0.0.1',
            port: peer.port,
            bindPort: probeBindPort,
            interfaceAddress: '127.0.0.1',
            joinMulticastGroup: false,
            initialJitterMs: 0,
            probeIntervalMs: 30,
            announceIntervalMs: 30,
            random: () => 0
        });
        assert.strictEqual(result.result, 'claimed');
        await new Promise((r) => setTimeout(r, 50));
        const probes = peer.received.filter((p) => p.header.qr === 0);
        const announces = peer.received.filter((p) => p.header.qr === 1);
        assert.strictEqual(probes.length, 3, 'three probe queries sent');
        assert.strictEqual(announces.length, 2, 'two announcements sent');
        const firstProbe = probes[0];
        assert.strictEqual(firstProbe.header.id, 0, 'mDNS multicast ID is 0');
        assert.strictEqual(firstProbe.questions.length, 1);
        assert.strictEqual(firstProbe.questions[0].type, PacketTypes.ANY);
        assert.notStrictEqual(firstProbe.questions[0].class & 0x8000, 0, 'QU bit set');
        assert.strictEqual(firstProbe.authorities.length, 1);
        assert.strictEqual(firstProbe.authorities[0].name, 'host.local');
        const firstAnn = announces[0];
        assert.strictEqual(firstAnn.header.aa, 1);
        assert.strictEqual(firstAnn.answers.length, 1);
        assert.notStrictEqual(firstAnn.answers[0].class & 0x8000, 0, 'cache-flush bit set');
    }
    finally {
        await closeSocket(peer.socket);
    }
});
test('MdnsProbe#claim flips to conflict when peer responds with different rdata', async () => {
    const peer = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    let peerPort = 0;
    let probeSenderAddr = null;
    let probeSenderPort = 0;
    peer.on('message', (msg, rinfo) => {
        try {
            const parsed = Packet.parse(msg);
            if (parsed.header.qr !== 0) {
                return;
            }
            const reply = new Packet();
            reply.header.qr = 1;
            reply.header.aa = 1;
            reply.answers = [aRec('host.local', '10.0.0.99')];
            probeSenderAddr = rinfo.address;
            probeSenderPort = rinfo.port;
            peer.send(reply.toBuffer(), rinfo.port, rinfo.address);
        }
        catch {
        }
    });
    await new Promise((r) => peer.bind(0, '127.0.0.1', () => {
        peerPort = peer.address().port;
        r();
    }));
    try {
        const probeSocket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
        await new Promise((r) => probeSocket.bind(0, '127.0.0.1', () => r()));
        const probeBindPort = probeSocket.address().port;
        await closeSocket(probeSocket);
        const result = await MdnsProbe.claim({
            records: [aRec('host.local', '10.0.0.1')],
            multicastAddr: '127.0.0.1',
            port: peerPort,
            bindPort: probeBindPort,
            interfaceAddress: '127.0.0.1',
            joinMulticastGroup: false,
            initialJitterMs: 0,
            probeIntervalMs: 100,
            random: () => 0
        });
        assert.strictEqual(result.result, 'conflict');
        assert.ok(result.conflictRecord !== undefined, 'conflict record reported');
        assert.strictEqual(result.conflictRecord.name, 'host.local');
        assert.strictEqual(result.conflictRecord.packetType.address, '10.0.0.99');
        assert.ok(result.conflictSource !== undefined, 'conflict source reported');
        assert.strictEqual(probeSenderAddr, '127.0.0.1');
        assert.strictEqual(probeSenderPort, probeBindPort);
    }
    finally {
        await closeSocket(peer);
    }
});
test('MdnsProbe#claim wins tiebreak when peer probe sorts earlier', async () => {
    const peer = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    let peerPort = 0;
    let receivedProbes = 0;
    peer.on('message', (msg, rinfo) => {
        try {
            const parsed = Packet.parse(msg);
            if (parsed.header.qr !== 0 || parsed.authorities.length === 0) {
                return;
            }
            receivedProbes++;
            if (receivedProbes === 1) {
                const competing = new Packet();
                competing.header.qr = 0;
                competing.header.id = 0;
                competing.questions = parsed.questions.slice();
                competing.authorities = [aRec('host.local', '10.0.0.1')];
                peer.send(competing.toBuffer(), rinfo.port, rinfo.address);
            }
        }
        catch {
        }
    });
    await new Promise((r) => peer.bind(0, '127.0.0.1', () => {
        peerPort = peer.address().port;
        r();
    }));
    try {
        const probeSocket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
        await new Promise((r) => probeSocket.bind(0, '127.0.0.1', () => r()));
        const probeBindPort = probeSocket.address().port;
        await closeSocket(probeSocket);
        const result = await MdnsProbe.claim({
            records: [aRec('host.local', '10.0.0.50')],
            multicastAddr: '127.0.0.1',
            port: peerPort,
            bindPort: probeBindPort,
            interfaceAddress: '127.0.0.1',
            joinMulticastGroup: false,
            initialJitterMs: 0,
            probeIntervalMs: 50,
            announceAttempts: 1,
            random: () => 0
        });
        assert.strictEqual(result.result, 'claimed', 'we sort later → we win the tiebreak');
    }
    finally {
        await closeSocket(peer);
    }
});
test('MdnsProbe#claim loses tiebreak when peer probe sorts later', async () => {
    const peer = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    let peerPort = 0;
    peer.on('message', (msg, rinfo) => {
        try {
            const parsed = Packet.parse(msg);
            if (parsed.header.qr !== 0 || parsed.authorities.length === 0) {
                return;
            }
            const competing = new Packet();
            competing.header.qr = 0;
            competing.header.id = 0;
            competing.questions = parsed.questions.slice();
            competing.authorities = [aRec('host.local', '10.0.0.99')];
            peer.send(competing.toBuffer(), rinfo.port, rinfo.address);
        }
        catch {
        }
    });
    await new Promise((r) => peer.bind(0, '127.0.0.1', () => {
        peerPort = peer.address().port;
        r();
    }));
    try {
        const probeSocket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
        await new Promise((r) => probeSocket.bind(0, '127.0.0.1', () => r()));
        const probeBindPort = probeSocket.address().port;
        await closeSocket(probeSocket);
        const result = await MdnsProbe.claim({
            records: [aRec('host.local', '10.0.0.1')],
            multicastAddr: '127.0.0.1',
            port: peerPort,
            bindPort: probeBindPort,
            interfaceAddress: '127.0.0.1',
            joinMulticastGroup: false,
            initialJitterMs: 0,
            probeIntervalMs: 100,
            random: () => 0
        });
        assert.strictEqual(result.result, 'conflict', 'peer sorts later → we lose');
        assert.strictEqual(result.conflictRecord.packetType.address, '10.0.0.99');
    }
    finally {
        await closeSocket(peer);
    }
});
test('MdnsProbe#claim ignores plain queries (no authority records) for the same name', async () => {
    const peer = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    let peerPort = 0;
    let probeCount = 0;
    peer.on('message', (msg, rinfo) => {
        try {
            const parsed = Packet.parse(msg);
            if (parsed.header.qr !== 0 || parsed.authorities.length === 0) {
                return;
            }
            probeCount++;
            const plain = new Packet();
            plain.header.qr = 0;
            plain.header.id = 0;
            plain.questions = parsed.questions.slice();
            peer.send(plain.toBuffer(), rinfo.port, rinfo.address);
        }
        catch {
        }
    });
    await new Promise((r) => peer.bind(0, '127.0.0.1', () => {
        peerPort = peer.address().port;
        r();
    }));
    try {
        const probeSocket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
        await new Promise((r) => probeSocket.bind(0, '127.0.0.1', () => r()));
        const probeBindPort = probeSocket.address().port;
        await closeSocket(probeSocket);
        const result = await MdnsProbe.claim({
            records: [aRec('host.local', '10.0.0.1')],
            multicastAddr: '127.0.0.1',
            port: peerPort,
            bindPort: probeBindPort,
            interfaceAddress: '127.0.0.1',
            joinMulticastGroup: false,
            initialJitterMs: 0,
            probeIntervalMs: 30,
            announceIntervalMs: 30,
            random: () => 0
        });
        assert.strictEqual(result.result, 'claimed');
        assert.strictEqual(probeCount, 3, 'all three of our probes reached the peer');
    }
    finally {
        await closeSocket(peer);
    }
});
test('MdnsProbe#claim rejects empty record list', async () => {
    await assert.rejects(MdnsProbe.claim({ records: [] }), /at least one tentative record/);
});
test('MdnsProbe#claim rejects records with mismatched names', async () => {
    await assert.rejects(MdnsProbe.claim({
        records: [
            aRec('foo.local', '10.0.0.1'),
            aRec('bar.local', '10.0.0.2')
        ]
    }), /must share one owner name/);
});
//# sourceMappingURL=mdnsProbe.js.map