import assert from 'assert';
import dgram from 'dgram';
import {ServiceDiscovery} from '../Client/ServiceDiscovery.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {AAAA} from '../Packet/Types/AAAA.js';
import {PTR} from '../Packet/Types/PTR.js';
import {SRV} from '../Packet/Types/SRV.js';
import {TXT} from '../Packet/Types/TXT.js';
import {test} from './test.js';

const bindLocalResponder = async(): Promise<{socket: dgram.Socket; port: number;}> => {
    return new Promise((resolve, reject) => {
        const socket = dgram.createSocket('udp4');
        socket.once('error', reject);
        socket.bind(0, '127.0.0.1', () => resolve({socket: socket, port: socket.address().port}));
    });
};

const ptrRec = (owner: string, target: string): PacketResource =>
    new PacketResource(owner, new PTR(target), PacketClass.IN, 120);

const srvRec = (owner: string, target: string, port: number): PacketResource =>
    new PacketResource(owner, new SRV(0, 0, port, target), PacketClass.IN, 120);

const txtRec = (owner: string, kv: string[]): PacketResource =>
    new PacketResource(owner, new TXT(kv), PacketClass.IN, 120);

const aRec = (owner: string, addr: string): PacketResource =>
    new PacketResource(owner, new A(addr), PacketClass.IN, 120);

const aaaaRec = (owner: string, addr: string): PacketResource =>
    new PacketResource(owner, new AAAA(addr), PacketClass.IN, 120);

const buildPtrReply = (
    query: Packet,
    answers: PacketResource[],
    additionals: PacketResource[] = []
): Packet => {
    const r = new Packet();
    r.header.qr = 1;
    r.header.aa = 1;
    r.questions = query.questions.slice();
    r.answers = answers;
    r.additionals = additionals;
    return r;
};

test('ServiceDiscovery#browse takes the bundled-additionals fast path', async() => {
    const {socket: responder, port} = await bindLocalResponder();

    responder.on('message', (msg, rinfo) => {
        const query = Packet.parse(msg);
        const q = query.questions[0];

        if (q.type === PacketTypes.PTR && q.name === '_http._tcp.local') {
            const reply = buildPtrReply(query, [
                ptrRec('_http._tcp.local', 'office._http._tcp.local')
            ], [
                // RFC 6763 §12 — bundle SRV + TXT + A in additionals.
                srvRec('office._http._tcp.local', 'office.local', 8080),
                txtRec('office._http._tcp.local', ['path=/admin', 'secure']),
                aRec('office.local', '192.168.1.10')
            ]);
            responder.send(reply.toBuffer(), rinfo.port, rinfo.address);
        }
    });

    try {
        const instances = await ServiceDiscovery.browse({
            serviceType: '_http._tcp',
            mdns: {
                multicastAddr: '127.0.0.1',
                port: port,
                timeoutMs: 200
            }
        });

        assert.equal(instances.length, 1);
        const inst = instances[0];
        assert.equal(inst.name, 'office._http._tcp.local');
        assert.equal(inst.host, 'office.local');
        assert.equal(inst.port, 8080);
        assert.deepEqual(inst.addresses, ['192.168.1.10']);
        assert.deepEqual(inst.txt, {path: '/admin', secure: true});
    } finally {
        responder.close();
    }
});

test('ServiceDiscovery#browse falls back to follow-up queries when no additionals', async() => {
    const {socket: responder, port} = await bindLocalResponder();

    responder.on('message', (msg, rinfo) => {
        const query = Packet.parse(msg);
        const q = query.questions[0];

        if (q.type === PacketTypes.PTR && q.name === '_http._tcp.local') {
            // PTR only — no bundled SRV/TXT/A.
            const reply = buildPtrReply(query, [
                ptrRec('_http._tcp.local', 'lonely._http._tcp.local')
            ]);
            responder.send(reply.toBuffer(), rinfo.port, rinfo.address);
        } else if (q.type === PacketTypes.SRV && q.name === 'lonely._http._tcp.local') {
            const reply = buildPtrReply(query, [
                srvRec('lonely._http._tcp.local', 'lonely.local', 9090)
            ]);
            responder.send(reply.toBuffer(), rinfo.port, rinfo.address);
        } else if (q.type === PacketTypes.TXT && q.name === 'lonely._http._tcp.local') {
            const reply = buildPtrReply(query, [
                txtRec('lonely._http._tcp.local', ['version=2'])
            ]);
            responder.send(reply.toBuffer(), rinfo.port, rinfo.address);
        } else if (q.type === PacketTypes.A && q.name === 'lonely.local') {
            const reply = buildPtrReply(query, [aRec('lonely.local', '10.0.0.5')]);
            responder.send(reply.toBuffer(), rinfo.port, rinfo.address);
        } else if (q.type === PacketTypes.AAAA && q.name === 'lonely.local') {
            const reply = buildPtrReply(query, [aaaaRec('lonely.local', '2001:db8::1')]);
            responder.send(reply.toBuffer(), rinfo.port, rinfo.address);
        }
    });

    try {
        const instances = await ServiceDiscovery.browse({
            serviceType: '_http._tcp',
            mdns: {
                multicastAddr: '127.0.0.1',
                port: port,
                timeoutMs: 100
            }
        });

        assert.equal(instances.length, 1);
        const inst = instances[0];
        assert.equal(inst.host, 'lonely.local');
        assert.equal(inst.port, 9090);
        assert.ok(inst.addresses.includes('10.0.0.5'));
        assert.ok(inst.addresses.includes('2001:db8::1'));
        assert.deepEqual(inst.txt, {version: '2'});
    } finally {
        responder.close();
    }
});

test('ServiceDiscovery#browse with resolveMissing:false skips follow-up queries', async() => {
    const {socket: responder, port} = await bindLocalResponder();
    let queryCount = 0;

    responder.on('message', (msg, rinfo) => {
        queryCount++;
        const query = Packet.parse(msg);
        const q = query.questions[0];

        if (q.type === PacketTypes.PTR) {
            const reply = buildPtrReply(query, [
                ptrRec('_http._tcp.local', 'sparse._http._tcp.local')
            ]);
            responder.send(reply.toBuffer(), rinfo.port, rinfo.address);
        }
    });

    try {
        const instances = await ServiceDiscovery.browse({
            serviceType: '_http._tcp',
            resolveMissing: false,
            mdns: {
                multicastAddr: '127.0.0.1',
                port: port,
                timeoutMs: 100
            }
        });

        assert.equal(instances.length, 1);
        assert.equal(instances[0].name, 'sparse._http._tcp.local');
        assert.equal(instances[0].host, undefined,
            'host stays undefined when resolveMissing is off and no SRV came in');
        assert.deepEqual(instances[0].addresses, []);
        // Exactly one query — the initial PTR. No follow-ups.
        assert.equal(queryCount, 1);
    } finally {
        responder.close();
    }
});

test('ServiceDiscovery#browse aggregates two PTR records into separate instances', async() => {
    const {socket: responder, port} = await bindLocalResponder();

    responder.on('message', (msg, rinfo) => {
        const query = Packet.parse(msg);
        const q = query.questions[0];

        if (q.type === PacketTypes.PTR && q.name === '_http._tcp.local') {
            const reply = buildPtrReply(query, [
                ptrRec('_http._tcp.local', 'a._http._tcp.local'),
                ptrRec('_http._tcp.local', 'b._http._tcp.local')
            ], [
                srvRec('a._http._tcp.local', 'host-a.local', 8080),
                srvRec('b._http._tcp.local', 'host-b.local', 9090),
                aRec('host-a.local', '10.0.0.1'),
                aRec('host-b.local', '10.0.0.2')
            ]);
            responder.send(reply.toBuffer(), rinfo.port, rinfo.address);
        }
    });

    try {
        const instances = await ServiceDiscovery.browse({
            serviceType: '_http._tcp',
            mdns: {
                multicastAddr: '127.0.0.1',
                port: port,
                timeoutMs: 200
            }
        });

        assert.equal(instances.length, 2);
        const byName = new Map(instances.map((i) => [i.name, i]));
        assert.equal(byName.get('a._http._tcp.local')!.host, 'host-a.local');
        assert.equal(byName.get('a._http._tcp.local')!.port, 8080);
        assert.deepEqual(byName.get('a._http._tcp.local')!.addresses, ['10.0.0.1']);
        assert.equal(byName.get('b._http._tcp.local')!.host, 'host-b.local');
        assert.equal(byName.get('b._http._tcp.local')!.port, 9090);
        assert.deepEqual(byName.get('b._http._tcp.local')!.addresses, ['10.0.0.2']);
    } finally {
        responder.close();
    }
});

test('ServiceDiscovery#browse returns empty list when nobody answers', async() => {
    const {socket, port} = await bindLocalResponder();
    socket.close();

    const instances = await ServiceDiscovery.browse({
        serviceType: '_http._tcp',
        mdns: {
            multicastAddr: '127.0.0.1',
            port: port,
            timeoutMs: 50
        }
    });

    assert.deepEqual(instances, []);
});

test('ServiceDiscovery#resolveInstance follows up with SRV + TXT + addresses', async() => {
    const {socket: responder, port} = await bindLocalResponder();

    responder.on('message', (msg, rinfo) => {
        const query = Packet.parse(msg);
        const q = query.questions[0];

        if (q.type === PacketTypes.SRV && q.name === 'tv._airplay._tcp.local') {
            const reply = buildPtrReply(query, [
                srvRec('tv._airplay._tcp.local', 'tv.local', 7000)
            ]);
            responder.send(reply.toBuffer(), rinfo.port, rinfo.address);
        } else if (q.type === PacketTypes.TXT && q.name === 'tv._airplay._tcp.local') {
            const reply = buildPtrReply(query, [
                txtRec('tv._airplay._tcp.local', ['vendor=Acme', 'model=A1'])
            ]);
            responder.send(reply.toBuffer(), rinfo.port, rinfo.address);
        } else if (q.type === PacketTypes.A && q.name === 'tv.local') {
            const reply = buildPtrReply(query, [aRec('tv.local', '192.168.1.42')]);
            responder.send(reply.toBuffer(), rinfo.port, rinfo.address);
        }
    });

    try {
        const inst = await ServiceDiscovery.resolveInstance('tv._airplay._tcp.local', {
            mdns: {
                multicastAddr: '127.0.0.1',
                port: port,
                timeoutMs: 100
            }
        });

        assert.equal(inst.name, 'tv._airplay._tcp.local');
        assert.equal(inst.host, 'tv.local');
        assert.equal(inst.port, 7000);
        assert.deepEqual(inst.addresses, ['192.168.1.42']);
        assert.deepEqual(inst.txt, {vendor: 'Acme', model: 'A1'});
    } finally {
        responder.close();
    }
});

test('ServiceDiscovery#TXT parsing — bare keys → true, key=value → string, dup keys first-wins', async() => {
    const {socket: responder, port} = await bindLocalResponder();

    responder.on('message', (msg, rinfo) => {
        const query = Packet.parse(msg);
        const q = query.questions[0];

        if (q.type === PacketTypes.PTR) {
            const reply = buildPtrReply(query, [
                ptrRec('_test._tcp.local', 'inst._test._tcp.local')
            ], [
                srvRec('inst._test._tcp.local', 'host.local', 1234),
                txtRec('inst._test._tcp.local', [
                    'flag',          // bare key → true
                    'name=alpha',    // key=value
                    'name=beta',     // duplicate → first-wins
                    '',              // empty entry — skipped
                    '=value-no-key', // empty key — skipped
                    'empty='         // empty value
                ]),
                aRec('host.local', '10.0.0.7')
            ]);
            responder.send(reply.toBuffer(), rinfo.port, rinfo.address);
        }
    });

    try {
        const [inst] = await ServiceDiscovery.browse({
            serviceType: '_test._tcp',
            mdns: {multicastAddr: '127.0.0.1', port: port, timeoutMs: 100}
        });

        assert.deepEqual(inst.txt, {
            flag: true,
            name: 'alpha',
            empty: ''
        });
    } finally {
        responder.close();
    }
});

test('ServiceDiscovery#browse honors a custom domain', async() => {
    const {socket: responder, port} = await bindLocalResponder();
    let lastQname: string | null = null;

    responder.on('message', (msg, rinfo) => {
        const query = Packet.parse(msg);
        lastQname = query.questions[0].name;

        if (query.questions[0].type === PacketTypes.PTR) {
            responder.send(buildPtrReply(query, []).toBuffer(), rinfo.port, rinfo.address);
        }
    });

    try {
        await ServiceDiscovery.browse({
            serviceType: '_imap._tcp',
            domain: 'example.com',
            mdns: {multicastAddr: '127.0.0.1', port: port, timeoutMs: 50}
        });

        assert.equal(lastQname, '_imap._tcp.example.com');
    } finally {
        responder.close();
    }
});