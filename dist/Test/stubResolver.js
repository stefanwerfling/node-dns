import assert from 'assert';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { RCODE } from '../Resolver/RecursiveResolver.js';
import { StubResolver } from '../Resolver/StubResolver.js';
import { test } from './test.js';
const buildResponse = (qname, qtype, rcode, answers = []) => {
    const p = new Packet();
    p.header.qr = 1;
    p.header.rcode = rcode;
    p.questions.push(new PacketQuestion(qname, qtype, PacketClass.IN));
    p.answers = answers;
    return p;
};
const recordingBackend = (router) => {
    const calls = [];
    const backend = async (name, _type, _cls) => {
        calls.push(name);
        return router(name);
    };
    return { backend: backend, calls: calls };
};
test('StubResolver#expand returns just the absolute name when name ends in dot', () => {
    const stub = new StubResolver({
        resolver: async () => new Packet(),
        search: ['example.com', 'corp.local'],
        ndots: 1
    });
    assert.deepStrictEqual(stub.expand('host.'), ['host']);
    assert.deepStrictEqual(stub.expand('host.sub.'), ['host.sub']);
});
test('StubResolver#expand short name (dots < ndots) tries search list first then absolute', () => {
    const stub = new StubResolver({
        resolver: async () => new Packet(),
        search: ['example.com', 'corp.local'],
        ndots: 2
    });
    assert.deepStrictEqual(stub.expand('host'), [
        'host.example.com',
        'host.corp.local',
        'host'
    ]);
    assert.deepStrictEqual(stub.expand('a.b'), [
        'a.b.example.com',
        'a.b.corp.local',
        'a.b'
    ]);
});
test('StubResolver#expand long name (dots >= ndots) tries absolute first then search list', () => {
    const stub = new StubResolver({
        resolver: async () => new Packet(),
        search: ['example.com'],
        ndots: 1
    });
    assert.deepStrictEqual(stub.expand('a.b'), [
        'a.b',
        'a.b.example.com'
    ]);
});
test('StubResolver#expand returns just the bare name when search list is empty', () => {
    const stub = new StubResolver({
        resolver: async () => new Packet(),
        search: [],
        ndots: 1
    });
    assert.deepStrictEqual(stub.expand('host'), ['host']);
    assert.deepStrictEqual(stub.expand('host.example.com'), ['host.example.com']);
});
test('StubResolver#expand normalizes trailing dots in search list and dedupes', () => {
    const stub = new StubResolver({
        resolver: async () => new Packet(),
        search: ['example.com.', 'example.com', 'corp.local.'],
        ndots: 1
    });
    assert.deepStrictEqual(stub.search, ['example.com', 'corp.local']);
    assert.deepStrictEqual(stub.expand('host'), [
        'host.example.com',
        'host.corp.local',
        'host'
    ]);
});
test('StubResolver#expand with ndots=0 disables search expansion entirely', () => {
    const stub = new StubResolver({
        resolver: async () => new Packet(),
        search: ['example.com'],
        ndots: 0
    });
    assert.deepStrictEqual(stub.expand('host'), ['host']);
});
test('StubResolver#resolve walks search list on NXDOMAIN and stops on NOERROR', async () => {
    const aRecord = new PacketResource('host.corp.local', new A('10.0.0.1'), PacketClass.IN, 60);
    const { backend, calls } = recordingBackend((name) => {
        if (name === 'host.corp.local') {
            return buildResponse(name, PacketTypes.A, RCODE.NOERROR, [aRecord]);
        }
        return buildResponse(name, PacketTypes.A, RCODE.NXDOMAIN);
    });
    const stub = new StubResolver({
        resolver: backend,
        search: ['example.com', 'corp.local'],
        ndots: 1
    });
    const response = await stub.resolve('host', PacketTypes.A);
    assert.strictEqual(response.header.rcode, RCODE.NOERROR);
    assert.strictEqual(response.questions[0].name, 'host.corp.local');
    assert.deepStrictEqual(calls, [
        'host.example.com',
        'host.corp.local'
    ]);
});
test('StubResolver#resolve halts on NODATA (NOERROR with empty answers) — does not advance', async () => {
    const { backend, calls } = recordingBackend((name) => {
        return buildResponse(name, PacketTypes.AAAA, RCODE.NOERROR, []);
    });
    const stub = new StubResolver({
        resolver: backend,
        search: ['example.com', 'corp.local'],
        ndots: 1
    });
    const response = await stub.resolve('host', PacketTypes.AAAA);
    assert.strictEqual(response.header.rcode, RCODE.NOERROR);
    assert.strictEqual(response.answers.length, 0);
    assert.deepStrictEqual(calls, ['host.example.com'], 'NODATA must be terminal — no further candidates queried');
});
test('StubResolver#resolve halts on SERVFAIL — does not silently mask upstream failure', async () => {
    const { backend, calls } = recordingBackend((name) => {
        return buildResponse(name, PacketTypes.A, RCODE.SERVFAIL);
    });
    const stub = new StubResolver({
        resolver: backend,
        search: ['example.com', 'corp.local'],
        ndots: 1
    });
    const response = await stub.resolve('host', PacketTypes.A);
    assert.strictEqual(response.header.rcode, RCODE.SERVFAIL);
    assert.deepStrictEqual(calls, ['host.example.com'], 'SERVFAIL must surface to caller — no fall-through');
});
test('StubResolver#resolve returns last NXDOMAIN when every candidate fails', async () => {
    const { backend, calls } = recordingBackend((name) => buildResponse(name, PacketTypes.A, RCODE.NXDOMAIN));
    const stub = new StubResolver({
        resolver: backend,
        search: ['example.com', 'corp.local'],
        ndots: 1
    });
    const response = await stub.resolve('host', PacketTypes.A);
    assert.strictEqual(response.header.rcode, RCODE.NXDOMAIN);
    assert.strictEqual(response.questions[0].name, 'host', 'last candidate is the bare name');
    assert.deepStrictEqual(calls, [
        'host.example.com',
        'host.corp.local',
        'host'
    ], 'every candidate exhausted before giving up');
});
test('StubResolver#resolve trailing-dot bypasses search list even on NXDOMAIN', async () => {
    const { backend, calls } = recordingBackend((name) => buildResponse(name, PacketTypes.A, RCODE.NXDOMAIN));
    const stub = new StubResolver({
        resolver: backend,
        search: ['example.com'],
        ndots: 1
    });
    const response = await stub.resolve('host.', PacketTypes.A);
    assert.strictEqual(response.header.rcode, RCODE.NXDOMAIN);
    assert.deepStrictEqual(calls, ['host'], 'fully-qualified name should not be search-expanded');
});
test('StubResolver#resolve long name tries absolute first then search list on NXDOMAIN', async () => {
    const { backend, calls } = recordingBackend((name) => {
        if (name === 'a.b.example.com') {
            return buildResponse(name, PacketTypes.A, RCODE.NOERROR, [
                new PacketResource(name, new A('10.0.0.7'), PacketClass.IN, 60)
            ]);
        }
        return buildResponse(name, PacketTypes.A, RCODE.NXDOMAIN);
    });
    const stub = new StubResolver({
        resolver: backend,
        search: ['example.com'],
        ndots: 1
    });
    const response = await stub.resolve('a.b', PacketTypes.A);
    assert.strictEqual(response.header.rcode, RCODE.NOERROR);
    assert.deepStrictEqual(calls, [
        'a.b',
        'a.b.example.com'
    ]);
});
test('StubResolver.fromConfig wires up nameservers/search/ndots from a parsed resolv.conf', async () => {
    const { backend, calls } = recordingBackend((name) => buildResponse(name, PacketTypes.A, RCODE.NXDOMAIN));
    const stub = StubResolver.fromConfig({
        nameservers: ['127.0.0.1'],
        search: ['internal.corp', 'corp.local'],
        sortlist: [],
        options: { ndots: 2 }
    }, backend);
    assert.strictEqual(stub.ndots, 2);
    assert.deepStrictEqual(stub.search, ['internal.corp', 'corp.local']);
    await stub.resolve('host', PacketTypes.A);
    assert.deepStrictEqual(calls, [
        'host.internal.corp',
        'host.corp.local',
        'host'
    ]);
});
test('StubResolver.fromConfig falls back to legacy `domain` when search list is empty', async () => {
    const { backend, calls } = recordingBackend((name) => buildResponse(name, PacketTypes.A, RCODE.NXDOMAIN));
    const stub = StubResolver.fromConfig({
        nameservers: ['127.0.0.1'],
        search: [],
        domain: 'legacy.local',
        sortlist: [],
        options: {}
    }, backend);
    assert.deepStrictEqual(stub.search, ['legacy.local']);
    await stub.resolve('host', PacketTypes.A);
    assert.deepStrictEqual(calls, ['host.legacy.local', 'host']);
});
test('StubResolver constructor rejects missing resolver function', () => {
    assert.throws(() => new StubResolver({}), /resolver is required/);
});
//# sourceMappingURL=stubResolver.js.map