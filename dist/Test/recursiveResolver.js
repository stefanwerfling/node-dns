import assert from 'assert';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { AAAA } from '../Packet/Types/AAAA.js';
import { CNAME } from '../Packet/Types/CNAME.js';
import { EDNS } from '../Packet/Types/EDNS.js';
import { NS } from '../Packet/Types/NS.js';
import { SOA } from '../Packet/Types/SOA.js';
import { DnsCache } from '../Resolver/DnsCache.js';
import { RCODE, RecursiveResolver } from '../Resolver/RecursiveResolver.js';
import { RootHints } from '../Resolver/RootHints.js';
import { test } from './test.js';
const TEST_ROOTS = [{ name: 'r.test.', ipv4: '10.0.0.1' }];
const aRec = (name, addr, ttl = 300) => new PacketResource(name, new A(addr), PacketClass.IN, ttl);
const aaaaRec = (name, addr, ttl = 300) => new PacketResource(name, new AAAA(addr), PacketClass.IN, ttl);
const nsRec = (owner, target, ttl = 300) => new PacketResource(owner, new NS(target), PacketClass.IN, ttl);
const cnameRec = (owner, target, ttl = 300) => new PacketResource(owner, new CNAME(target), PacketClass.IN, ttl);
const soaRec = (owner, ttl = 300, minimum = 60) => {
    const soa = new SOA();
    soa.primary = 'ns.test.';
    soa.admin = 'admin.test.';
    soa.serial = 1;
    soa.refresh = 7200;
    soa.retry = 3600;
    soa.expiration = 1209600;
    soa.minimum = minimum;
    return new PacketResource(owner, soa, PacketClass.IN, ttl);
};
const buildAnswer = (query, answers, options = {}) => {
    const r = new Packet();
    r.header.id = query.header.id;
    r.header.qr = 1;
    r.header.aa = options.aa === false ? 0 : 1;
    r.header.rcode = options.rcode ?? 0;
    r.questions = query.questions.slice();
    r.answers = answers;
    r.authorities = options.authorities ?? [];
    r.additionals = options.additionals ?? [];
    return r;
};
const buildReferral = (query, childZone, nsList, glue) => {
    const r = new Packet();
    r.header.id = query.header.id;
    r.header.qr = 1;
    r.header.aa = 0;
    r.questions = query.questions.slice();
    r.authorities = nsList.map((n) => nsRec(childZone, n));
    r.additionals = glue;
    return r;
};
class MockTransport {
    routes = new Map();
    catchAll = new Map();
    callsByServer = new Map();
    on(server, qname, handler) {
        if (!this.routes.has(server)) {
            this.routes.set(server, new Map());
        }
        this.routes.get(server).set(MockTransport._norm(qname), handler);
        return this;
    }
    static _norm(name) {
        const stripped = name.endsWith('.') && name.length > 1 ? name.slice(0, -1) : name;
        return stripped.toLowerCase();
    }
    default(server, handler) {
        this.catchAll.set(server, handler);
        return this;
    }
    count(server) {
        return this.callsByServer.get(server) ?? 0;
    }
    asTransport() {
        return async (serverIp, _port, query) => {
            this.callsByServer.set(serverIp, (this.callsByServer.get(serverIp) ?? 0) + 1);
            const byServer = this.routes.get(serverIp);
            const qname = MockTransport._norm(query.questions[0].name);
            const exact = byServer?.get(qname);
            if (exact !== undefined) {
                return exact(query);
            }
            const fallback = this.catchAll.get(serverIp);
            if (fallback !== undefined) {
                return fallback(query);
            }
            throw new Error(`MockTransport: no route for ${serverIp} / ${qname}`);
        };
    }
}
test('RecursiveResolver#cache hit returns immediately without queries', async () => {
    const cache = new DnsCache();
    cache.set('cached.example.com', PacketTypes.A, PacketClass.IN, [aRec('cached.example.com', '192.0.2.99')], 60);
    const transport = new MockTransport();
    const resolver = new RecursiveResolver({
        cache: cache,
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    const r = await resolver.resolve('cached.example.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.NOERROR);
    assert.equal(r.answers.length, 1);
    assert.equal(r.answers[0].packetType.address, '192.0.2.99');
    assert.equal(transport.count('10.0.0.1'), 0);
});
test('RecursiveResolver#full chain: root → tld → auth (happy path)', async () => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => buildReferral(q, 'com.', ['a.gtld.com.'], [aRec('a.gtld.com.', '10.0.0.2')]));
    transport.default('10.0.0.2', (q) => buildReferral(q, 'example.com.', ['ns.example.com.'], [aRec('ns.example.com.', '10.0.0.3')]));
    transport.on('10.0.0.3', 'www.example.com', (q) => buildAnswer(q, [
        aRec('www.example.com', '198.51.100.7')
    ]));
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    const r = await resolver.resolve('www.example.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.NOERROR);
    assert.equal(r.answers.length, 1);
    assert.equal(r.answers[0].packetType.address, '198.51.100.7');
    assert.equal(transport.count('10.0.0.1'), 1);
    assert.equal(transport.count('10.0.0.2'), 1);
    assert.equal(transport.count('10.0.0.3'), 1);
});
test('RecursiveResolver#NXDOMAIN propagates from authoritative response', async () => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'], [aRec('auth.test.', '10.0.0.2')]));
    transport.default('10.0.0.2', (q) => buildAnswer(q, [], {
        rcode: RCODE.NXDOMAIN,
        authorities: [soaRec('example.com.', 3600, 60)]
    }));
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    const r = await resolver.resolve('absent.example.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.NXDOMAIN);
    assert.equal(r.answers.length, 0);
});
test('RecursiveResolver#NXDOMAIN is negatively cached (no 2nd upstream)', async () => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'], [aRec('auth.test.', '10.0.0.2')]));
    transport.default('10.0.0.2', (q) => buildAnswer(q, [], {
        rcode: RCODE.NXDOMAIN,
        authorities: [soaRec('example.com.', 3600, 60)]
    }));
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    await resolver.resolve('absent.example.com', PacketTypes.A);
    const before = transport.count('10.0.0.2');
    const r2 = await resolver.resolve('absent.example.com', PacketTypes.A);
    assert.equal(r2.header.rcode, RCODE.NXDOMAIN);
    assert.equal(transport.count('10.0.0.2'), before, 'second query must hit the cache');
});
test('RecursiveResolver#NODATA (NOERROR + empty + SOA) propagates', async () => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'], [aRec('auth.test.', '10.0.0.2')]));
    transport.default('10.0.0.2', (q) => buildAnswer(q, [], {
        rcode: RCODE.NOERROR,
        authorities: [soaRec('example.com.', 3600, 60)]
    }));
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    const r = await resolver.resolve('host.example.com', PacketTypes.MX);
    assert.equal(r.header.rcode, RCODE.NOERROR);
    assert.equal(r.answers.length, 0);
});
test('RecursiveResolver#follows CNAME chain', async () => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'], [aRec('auth.test.', '10.0.0.2')]));
    transport.on('10.0.0.2', 'www.example.com', (q) => buildAnswer(q, [
        cnameRec('www.example.com', 'real.example.com.')
    ]));
    transport.on('10.0.0.2', 'real.example.com', (q) => buildAnswer(q, [
        aRec('real.example.com', '203.0.113.5')
    ]));
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    const r = await resolver.resolve('www.example.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.NOERROR);
    assert.equal(r.answers.length, 2);
    assert.ok(r.answers[0].packetType instanceof CNAME);
    assert.ok(r.answers[1].packetType instanceof A);
    assert.equal(r.answers[1].packetType.address, '203.0.113.5');
});
test('RecursiveResolver#CNAME chain in single response is returned directly', async () => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'], [aRec('auth.test.', '10.0.0.2')]));
    transport.on('10.0.0.2', 'alias.example.com', (q) => buildAnswer(q, [
        cnameRec('alias.example.com', 'real.example.com.'),
        aRec('real.example.com', '203.0.113.5')
    ]));
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    const r = await resolver.resolve('alias.example.com', PacketTypes.A);
    assert.equal(r.answers.length, 2);
    assert.equal(transport.count('10.0.0.2'), 1);
});
test('RecursiveResolver#bailiwick filter strips out-of-zone records from sibling-injection', async () => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => buildReferral(q, 'com.', ['a.gtld.com.'], [aRec('a.gtld.com.', '10.0.0.2')]));
    transport.default('10.0.0.2', (q) => buildReferral(q, 'example.com.', ['ns.example.com.'], [
        aRec('ns.example.com.', '10.0.0.3'),
        aRec('victim.example.org.', '6.6.6.6')
    ]));
    transport.on('10.0.0.3', 'www.example.com', (q) => buildAnswer(q, [
        aRec('www.example.com', '198.51.100.7')
    ]));
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    await resolver.resolve('www.example.com', PacketTypes.A);
    assert.equal(resolver.cache().get('victim.example.org', PacketTypes.A, PacketClass.IN), null);
    const ns = resolver.cache().get('ns.example.com', PacketTypes.A, PacketClass.IN);
    assert.ok(ns);
});
test('RecursiveResolver#0x20 case-mismatch response is rejected', async () => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => {
        const lowered = new PacketQuestion(q.questions[0].name.toLowerCase(), q.questions[0].type, q.questions[0].class);
        const r = new Packet();
        r.header.id = q.header.id;
        r.header.qr = 1;
        r.header.aa = 1;
        r.questions = [lowered];
        r.answers = [aRec(lowered.name, '198.51.100.7')];
        return r;
    });
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: true
    });
    const r = await resolver.resolve('Mixed.Case.Test', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.SERVFAIL);
});
test('RecursiveResolver#response ID mismatch is rejected', async () => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => {
        const r = new Packet();
        r.header.id = (q.header.id + 1) & 0xFFFF;
        r.header.qr = 1;
        r.questions = q.questions.slice();
        r.answers = [aRec('x.test', '1.2.3.4')];
        return r;
    });
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    const r = await resolver.resolve('x.test', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.SERVFAIL);
});
test('RecursiveResolver#max-queries budget aborts misbehaving zone', async () => {
    const transport = new MockTransport();
    let depth = 0;
    transport.default('10.0.0.1', (q) => buildReferral(q, `${depth++}.example.com.`, ['r.test.'], [aRec('r.test.', '10.0.0.1')]));
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false,
        maxQueries: 5
    });
    const r = await resolver.resolve('deep.example.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.SERVFAIL);
});
test('RecursiveResolver#cached CNAME is followed without re-querying', async () => {
    const cache = new DnsCache();
    cache.set('alias.test', PacketTypes.CNAME, PacketClass.IN, [cnameRec('alias.test', 'real.test.')], 300);
    cache.set('real.test', PacketTypes.A, PacketClass.IN, [aRec('real.test', '198.51.100.99')], 300);
    const transport = new MockTransport();
    const resolver = new RecursiveResolver({
        cache: cache,
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    const r = await resolver.resolve('alias.test', PacketTypes.A);
    assert.equal(r.answers.length, 2);
    assert.equal(r.answers[1].packetType.address, '198.51.100.99');
    assert.equal(transport.count('10.0.0.1'), 0);
});
test('RecursiveResolver#cache() exposes underlying cache instance', () => {
    const cache = new DnsCache();
    const r = new RecursiveResolver({ cache: cache, rootHints: TEST_ROOTS });
    assert.strictEqual(r.cache(), cache);
});
test('RecursiveResolver#constructor primes the cache with root NS', () => {
    const r = new RecursiveResolver({ rootHints: TEST_ROOTS });
    const rootNs = r.cache().get('.', PacketTypes.NS, PacketClass.IN);
    assert.ok(rootNs);
    assert.equal(rootNs.records.length, 1);
});
test('RecursiveResolver#bundled DEFAULT root hints prime when not overridden', () => {
    const r = new RecursiveResolver();
    const rootNs = r.cache().get('.', PacketTypes.NS, PacketClass.IN);
    assert.ok(rootNs);
    assert.equal(rootNs.records.length, RootHints.DEFAULT.length);
});
test('RecursiveResolver#glueless out-of-bailiwick NS triggers sub-resolution', async () => {
    const transport = new MockTransport();
    const norm = (n) => (n.endsWith('.') && n.length > 1 ? n.slice(0, -1) : n).toLowerCase();
    transport.default('10.0.0.1', (q) => {
        if (norm(q.questions[0].name) === 'ns.other.test') {
            return buildReferral(q, 'other.test.', ['gtld.test.'], [aRec('gtld.test.', '10.0.0.2')]);
        }
        return buildReferral(q, 'example.com.', ['ns.other.test.'], []);
    });
    transport.on('10.0.0.2', 'ns.other.test', (q) => buildAnswer(q, [
        aRec('ns.other.test', '10.0.0.3')
    ]));
    transport.on('10.0.0.3', 'www.example.com', (q) => buildAnswer(q, [
        aRec('www.example.com', '198.51.100.42')
    ]));
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false,
        qnameMinimization: false
    });
    const r = await resolver.resolve('www.example.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.NOERROR);
    assert.equal(r.answers[0].packetType.address, '198.51.100.42');
});
test('RecursiveResolver#OPT pseudo-records are not cached', async () => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'], [aRec('auth.test.', '10.0.0.2')]));
    transport.on('10.0.0.2', 'www.example.com', (q) => buildAnswer(q, [
        aRec('www.example.com', '198.51.100.7')
    ]));
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    await resolver.resolve('www.example.com', PacketTypes.A);
    assert.equal(resolver.cache().get('', PacketTypes.EDNS, PacketClass.IN), null);
});
test('RecursiveResolver#min TTL of an RRset is what gets cached', async () => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'], [aRec('auth.test.', '10.0.0.2', 600)]));
    transport.on('10.0.0.2', 'multi.example.com', (q) => buildAnswer(q, [
        aRec('multi.example.com', '1.1.1.1', 100),
        aRec('multi.example.com', '2.2.2.2', 50),
        aRec('multi.example.com', '3.3.3.3', 200)
    ]));
    let now = 1_000_000;
    const cache = new DnsCache({ now: () => now });
    const resolver = new RecursiveResolver({
        cache: cache,
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    await resolver.resolve('multi.example.com', PacketTypes.A);
    const entry = cache.get('multi.example.com', PacketTypes.A, PacketClass.IN);
    assert.equal(entry.expiresAt, 1_000_000 + 50_000);
});
test('RecursiveResolver#TC=1 triggers TCP retry that returns full answer', async () => {
    const udp = new MockTransport();
    const tcp = new MockTransport();
    udp.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'], [aRec('auth.test.', '10.0.0.2')]));
    udp.on('10.0.0.2', 'big.example.com', (q) => {
        const r = new Packet();
        r.header.id = q.header.id;
        r.header.qr = 1;
        r.header.aa = 1;
        r.header.tc = 1;
        r.questions = q.questions.slice();
        r.answers = [];
        return r;
    });
    tcp.on('10.0.0.2', 'big.example.com', (q) => buildAnswer(q, [
        aRec('big.example.com', '198.51.100.1'),
        aRec('big.example.com', '198.51.100.2'),
        aRec('big.example.com', '198.51.100.3')
    ]));
    const resolver = new RecursiveResolver({
        transport: udp.asTransport(),
        tcpTransport: tcp.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    const r = await resolver.resolve('big.example.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.NOERROR);
    assert.equal(r.answers.length, 3);
    assert.equal(udp.count('10.0.0.2'), 1);
    assert.equal(tcp.count('10.0.0.2'), 1);
});
test('RecursiveResolver#TC=1 does not retry when tcpFallback is disabled', async () => {
    const udp = new MockTransport();
    const tcp = new MockTransport();
    udp.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'], [aRec('auth.test.', '10.0.0.2')]));
    udp.on('10.0.0.2', 'big.example.com', (q) => {
        const r = new Packet();
        r.header.id = q.header.id;
        r.header.qr = 1;
        r.header.aa = 1;
        r.header.tc = 1;
        r.questions = q.questions.slice();
        r.answers = [aRec('big.example.com', '198.51.100.1')];
        return r;
    });
    tcp.on('10.0.0.2', 'big.example.com', () => {
        throw new Error('TCP transport must not be used when tcpFallback is disabled');
    });
    const resolver = new RecursiveResolver({
        transport: udp.asTransport(),
        tcpTransport: tcp.asTransport(),
        tcpFallback: false,
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    const r = await resolver.resolve('big.example.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.NOERROR);
    assert.equal(udp.count('10.0.0.2'), 1);
    assert.equal(tcp.count('10.0.0.2'), 0);
});
test('RecursiveResolver#TCP transport failure surfaces as SERVFAIL', async () => {
    const udp = new MockTransport();
    const tcp = new MockTransport();
    udp.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'], [aRec('auth.test.', '10.0.0.2')]));
    udp.on('10.0.0.2', 'big.example.com', (q) => {
        const r = new Packet();
        r.header.id = q.header.id;
        r.header.qr = 1;
        r.header.aa = 1;
        r.header.tc = 1;
        r.questions = q.questions.slice();
        r.answers = [];
        return r;
    });
    tcp.on('10.0.0.2', 'big.example.com', () => {
        throw new Error('connection refused');
    });
    const resolver = new RecursiveResolver({
        transport: udp.asTransport(),
        tcpTransport: tcp.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    const r = await resolver.resolve('big.example.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.SERVFAIL);
});
test('RecursiveResolver#TCP retry counts toward query budget', async () => {
    const udp = new MockTransport();
    const tcp = new MockTransport();
    udp.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'], [aRec('auth.test.', '10.0.0.2')]));
    udp.on('10.0.0.2', 'big.example.com', (q) => {
        const r = new Packet();
        r.header.id = q.header.id;
        r.header.qr = 1;
        r.header.aa = 1;
        r.header.tc = 1;
        r.questions = q.questions.slice();
        return r;
    });
    tcp.on('10.0.0.2', 'big.example.com', (q) => buildAnswer(q, [
        aRec('big.example.com', '198.51.100.1')
    ]));
    const resolver = new RecursiveResolver({
        transport: udp.asTransport(),
        tcpTransport: tcp.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false,
        maxQueries: 2
    });
    const r = await resolver.resolve('big.example.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.SERVFAIL);
});
test('RecursiveResolver#AAAA glue is used when no A is available', async () => {
    const transport = new MockTransport();
    transport.default('::1', (q) => buildAnswer(q, [
        aRec('only-v6.test', '198.51.100.10')
    ]));
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: [{ name: 'r.test.', ipv4: '0.0.0.0', ipv6: '::1' }],
        use0x20: false,
        qnameMinimization: false
    });
    resolver.cache().delete('r.test', PacketTypes.A, PacketClass.IN);
    const r = await resolver.resolve('only-v6.test', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.NOERROR);
    assert.equal(transport.count('::1'), 1);
});
test('RecursiveResolver#outgoing query carries EDNS OPT with default 4096 buffer', async () => {
    const seen = [];
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => {
        seen.push(q);
        return buildAnswer(q, [aRec('host.test', '198.51.100.1')]);
    });
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    await resolver.resolve('host.test', PacketTypes.A);
    assert.equal(seen.length, 1);
    const opt = seen[0].additionals.find((r) => r.packetType instanceof EDNS);
    assert.ok(opt, 'outgoing query must carry an OPT RR');
    assert.equal(opt.class, 4096);
});
test('RecursiveResolver#udpPayloadSize override flows into the OPT', async () => {
    const seen = [];
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => {
        seen.push(q);
        return buildAnswer(q, [aRec('host.test', '198.51.100.1')]);
    });
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false,
        udpPayloadSize: 1232
    });
    await resolver.resolve('host.test', PacketTypes.A);
    const opt = seen[0].additionals.find((r) => r.packetType instanceof EDNS);
    assert.ok(opt);
    assert.equal(opt.class, 1232);
});
test('RecursiveResolver#useEdns:false suppresses the OPT RR', async () => {
    const seen = [];
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => {
        seen.push(q);
        return buildAnswer(q, [aRec('host.test', '198.51.100.1')]);
    });
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false,
        useEdns: false
    });
    await resolver.resolve('host.test', PacketTypes.A);
    assert.equal(seen[0].additionals.find((r) => r.packetType instanceof EDNS), undefined);
});
test('RecursiveResolver#response OPT is not cached as an RRset', async () => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => {
        const r = buildAnswer(q, [aRec('host.test', '198.51.100.1')]);
        r.additionals.push(EDNS.createResource([], 1232));
        return r;
    });
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    await resolver.resolve('host.test', PacketTypes.A);
    assert.ok(resolver.cache().get('host.test', PacketTypes.A, PacketClass.IN));
    assert.equal(resolver.cache().get('', PacketTypes.EDNS, PacketClass.IN), null);
});
test('RecursiveResolver#DO bit clear when DNSSEC validation is disabled', async () => {
    const seen = [];
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => {
        seen.push(q);
        return buildAnswer(q, [aRec('host.test', '198.51.100.1')]);
    });
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    await resolver.resolve('host.test', PacketTypes.A);
    const opt = seen[0].additionals.find((r) => r.packetType instanceof EDNS);
    assert.ok(opt);
    assert.equal(opt.ttl & 0x00008000, 0);
});
test('RecursiveResolver#DO bit set when DNSSEC validation is enabled', async () => {
    const seen = [];
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => {
        seen.push(q);
        return buildAnswer(q, [aRec('host.test', '198.51.100.1')]);
    });
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false,
        dnssec: true
    });
    await resolver.resolve('host.test', PacketTypes.A);
    const opt = seen[0].additionals.find((r) => r.packetType instanceof EDNS);
    assert.ok(opt);
    assert.equal(opt.ttl & 0x00008000, 0x00008000);
});
test('RecursiveResolver#smaller server-advertised buffer downgrades the next query', async () => {
    const seen = [];
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => {
        seen.push(q);
        const r = buildAnswer(q, [aRec('host.test', '198.51.100.1')]);
        r.additionals.push(EDNS.createResource([], 1232));
        return r;
    });
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false,
        udpPayloadSize: 4096
    });
    await resolver.resolve('host.test', PacketTypes.A);
    let opt = seen[0].additionals.find((r) => r.packetType instanceof EDNS);
    assert.ok(opt);
    assert.equal(opt.class, 4096);
    await resolver.resolve('other.test', PacketTypes.A);
    opt = seen[1].additionals.find((r) => r.packetType instanceof EDNS);
    assert.ok(opt);
    assert.equal(opt.class, 1232, 'second query must respect the server-advertised buffer');
});
test('RecursiveResolver#larger server-advertised buffer does NOT upgrade past our default', async () => {
    const seen = [];
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => {
        seen.push(q);
        const r = buildAnswer(q, [aRec('host.test', '198.51.100.1')]);
        r.additionals.push(EDNS.createResource([], 8192));
        return r;
    });
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false,
        udpPayloadSize: 4096
    });
    await resolver.resolve('host.test', PacketTypes.A);
    await resolver.resolve('other.test', PacketTypes.A);
    const opt = seen[1].additionals.find((r) => r.packetType instanceof EDNS);
    assert.ok(opt);
    assert.equal(opt.class, 4096);
});
test('RecursiveResolver#missing OPT in response leaves our default unchanged', async () => {
    const seen = [];
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => {
        seen.push(q);
        return buildAnswer(q, [aRec('host.test', '198.51.100.1')]);
    });
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    await resolver.resolve('host.test', PacketTypes.A);
    await resolver.resolve('other.test', PacketTypes.A);
    const opt = seen[1].additionals.find((r) => r.packetType instanceof EDNS);
    assert.ok(opt);
    assert.equal(opt.class, 4096);
});
test('RecursiveResolver#stale cache hit is returned immediately and triggers a background refresh', async () => {
    let now = 1_000_000;
    const cache = new DnsCache({ now: () => now, maxStaleSeconds: 300 });
    cache.set('stale.test', PacketTypes.A, PacketClass.IN, [aRec('stale.test', '192.0.2.1')], 60);
    now += 70_000;
    const transport = new MockTransport();
    let refreshCalls = 0;
    transport.default('10.0.0.1', (q) => buildReferral(q, 'test.', ['auth.test.'], [aRec('auth.test.', '10.0.0.2')]));
    transport.on('10.0.0.2', 'stale.test', (q) => {
        refreshCalls++;
        return buildAnswer(q, [aRec('stale.test', '192.0.2.99')]);
    });
    const resolver = new RecursiveResolver({
        cache: cache,
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    const r = await resolver.resolve('stale.test', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.NOERROR);
    assert.equal(r.answers[0].packetType.address, '192.0.2.1', 'caller must see the stale record on the original request');
    for (let i = 0; i < 10; i++) {
        await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(refreshCalls, 1, 'background refresh must have hit the upstream auth');
    now += 1_000;
    const fresh = cache.get('stale.test', PacketTypes.A, PacketClass.IN);
    assert.ok(fresh);
    assert.notEqual(fresh.stale, true);
    assert.equal(fresh.records[0].packetType.address, '192.0.2.99');
});
test('RecursiveResolver#concurrent stale hits dedupe the refresh', async () => {
    let now = 1_000_000;
    const cache = new DnsCache({ now: () => now, maxStaleSeconds: 300 });
    cache.set('stale.test', PacketTypes.A, PacketClass.IN, [aRec('stale.test', '192.0.2.1')], 60);
    now += 70_000;
    const transport = new MockTransport();
    let refreshCalls = 0;
    transport.default('10.0.0.1', (q) => buildReferral(q, 'test.', ['auth.test.'], [aRec('auth.test.', '10.0.0.2')]));
    transport.on('10.0.0.2', 'stale.test', (q) => {
        refreshCalls++;
        return buildAnswer(q, [aRec('stale.test', '192.0.2.99')]);
    });
    const resolver = new RecursiveResolver({
        cache: cache,
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    await Promise.all([
        resolver.resolve('stale.test', PacketTypes.A),
        resolver.resolve('stale.test', PacketTypes.A),
        resolver.resolve('stale.test', PacketTypes.A)
    ]);
    for (let i = 0; i < 10; i++) {
        await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(refreshCalls, 1);
});
test('RecursiveResolver#prefetch hit returns the still-fresh record + schedules a refresh', async () => {
    let now = 1_000_000;
    const cache = new DnsCache({ now: () => now, prefetchThreshold: 0.2 });
    cache.set('hot.test', PacketTypes.A, PacketClass.IN, [aRec('hot.test', '192.0.2.1')], 60);
    now += 54_000;
    const transport = new MockTransport();
    let refreshCalls = 0;
    transport.default('10.0.0.1', (q) => buildReferral(q, 'test.', ['auth.test.'], [aRec('auth.test.', '10.0.0.2')]));
    transport.on('10.0.0.2', 'hot.test', (q) => {
        refreshCalls++;
        return buildAnswer(q, [aRec('hot.test', '192.0.2.99')]);
    });
    const resolver = new RecursiveResolver({
        cache: cache,
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    const r = await resolver.resolve('hot.test', PacketTypes.A);
    assert.equal(r.answers[0].packetType.address, '192.0.2.1', 'caller still gets the fresh-but-near-expiry record');
    for (let i = 0; i < 10; i++) {
        await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(refreshCalls, 1, 'prefetch fires exactly one upstream refresh');
    now += 1_000;
    const fresh = cache.get('hot.test', PacketTypes.A, PacketClass.IN);
    assert.ok(fresh);
    assert.equal(fresh.records[0].packetType.address, '192.0.2.99');
});
test('RecursiveResolver#prefetch dedup shares the in-flight set with stale-while-revalidate', async () => {
    let now = 1_000_000;
    const cache = new DnsCache({ now: () => now, prefetchThreshold: 0.2 });
    cache.set('hot.test', PacketTypes.A, PacketClass.IN, [aRec('hot.test', '192.0.2.1')], 60);
    now += 54_000;
    const transport = new MockTransport();
    let refreshCalls = 0;
    transport.default('10.0.0.1', (q) => buildReferral(q, 'test.', ['auth.test.'], [aRec('auth.test.', '10.0.0.2')]));
    transport.on('10.0.0.2', 'hot.test', (q) => {
        refreshCalls++;
        return buildAnswer(q, [aRec('hot.test', '192.0.2.99')]);
    });
    const resolver = new RecursiveResolver({
        cache: cache,
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    await Promise.all([
        resolver.resolve('hot.test', PacketTypes.A),
        resolver.resolve('hot.test', PacketTypes.A),
        resolver.resolve('hot.test', PacketTypes.A),
        resolver.resolve('hot.test', PacketTypes.A),
        resolver.resolve('hot.test', PacketTypes.A)
    ]);
    for (let i = 0; i < 10; i++) {
        await new Promise((resolve) => setImmediate(resolve));
    }
    assert.equal(refreshCalls, 1, 'concurrent prefetch hits dedupe to a single refresh');
});
test('RecursiveResolver#stale-while-revalidate disabled by default — expired entries trigger full re-resolution', async () => {
    let now = 1_000_000;
    const cache = new DnsCache({ now: () => now });
    cache.set('stale.test', PacketTypes.A, PacketClass.IN, [aRec('stale.test', '192.0.2.1')], 60);
    now += 70_000;
    const transport = new MockTransport();
    let upstreamCalls = 0;
    transport.default('10.0.0.1', (q) => buildReferral(q, 'test.', ['auth.test.'], [aRec('auth.test.', '10.0.0.2')]));
    transport.on('10.0.0.2', 'stale.test', (q) => {
        upstreamCalls++;
        return buildAnswer(q, [aRec('stale.test', '192.0.2.99')]);
    });
    const resolver = new RecursiveResolver({
        cache: cache,
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });
    const r = await resolver.resolve('stale.test', PacketTypes.A);
    assert.equal(r.answers[0].packetType.address, '192.0.2.99');
    assert.equal(upstreamCalls, 1);
});
const recordingTransport = (sent, inner) => async (serverIp, port, query) => {
    sent.push({
        server: serverIp,
        qname: query.questions[0].name,
        qtype: query.questions[0].type
    });
    return inner(serverIp, port, query);
};
test('RecursiveResolver#qname minimization sends NS probes to root + TLD, full qname only to auth', async () => {
    const sent = [];
    const transport = new MockTransport();
    transport.on('10.0.0.1', 'com', (q) => buildReferral(q, 'com.', ['a.gtld.com.'], [aRec('a.gtld.com.', '10.0.0.2')]));
    transport.on('10.0.0.2', 'example.com', (q) => buildReferral(q, 'example.com.', ['ns.example.com.'], [aRec('ns.example.com.', '10.0.0.3')]));
    transport.on('10.0.0.3', 'www.example.com', (q) => buildAnswer(q, [
        aRec('www.example.com', '198.51.100.42')
    ]));
    const resolver = new RecursiveResolver({
        transport: recordingTransport(sent, transport.asTransport()),
        rootHints: TEST_ROOTS,
        use0x20: false,
        qnameMinimization: true
    });
    const r = await resolver.resolve('www.example.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.NOERROR);
    assert.equal(r.answers[0].packetType.address, '198.51.100.42');
    assert.equal(sent.length, 3, 'three hops: root, com, auth');
    assert.equal(sent[0].server, '10.0.0.1');
    assert.equal(sent[0].qname.toLowerCase().replace(/\.$/, ''), 'com');
    assert.equal(sent[0].qtype, PacketTypes.NS);
    assert.equal(sent[1].server, '10.0.0.2');
    assert.equal(sent[1].qname.toLowerCase().replace(/\.$/, ''), 'example.com');
    assert.equal(sent[1].qtype, PacketTypes.NS);
    assert.equal(sent[2].server, '10.0.0.3');
    assert.equal(sent[2].qname.toLowerCase().replace(/\.$/, ''), 'www.example.com');
    assert.equal(sent[2].qtype, PacketTypes.A);
});
test('RecursiveResolver#qname minimization disabled sends full qname to every hop', async () => {
    const sent = [];
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => buildReferral(q, 'com.', ['a.gtld.com.'], [aRec('a.gtld.com.', '10.0.0.2')]));
    transport.default('10.0.0.2', (q) => buildReferral(q, 'example.com.', ['ns.example.com.'], [aRec('ns.example.com.', '10.0.0.3')]));
    transport.on('10.0.0.3', 'www.example.com', (q) => buildAnswer(q, [
        aRec('www.example.com', '198.51.100.42')
    ]));
    const resolver = new RecursiveResolver({
        transport: recordingTransport(sent, transport.asTransport()),
        rootHints: TEST_ROOTS,
        use0x20: false,
        qnameMinimization: false
    });
    await resolver.resolve('www.example.com', PacketTypes.A);
    assert.equal(sent.length, 3);
    for (const s of sent) {
        assert.equal(s.qname.toLowerCase().replace(/\.$/, ''), 'www.example.com');
        assert.equal(s.qtype, PacketTypes.A);
    }
});
test('RecursiveResolver#qname minimization NXDOMAIN at intermediate prefix terminates with NXDOMAIN', async () => {
    const sent = [];
    const transport = new MockTransport();
    transport.on('10.0.0.1', 'com', (q) => buildReferral(q, 'com.', ['a.gtld.com.'], [aRec('a.gtld.com.', '10.0.0.2')]));
    transport.on('10.0.0.2', 'absent.com', (q) => buildAnswer(q, [], {
        rcode: RCODE.NXDOMAIN,
        authorities: [soaRec('com', 3600, 60)]
    }));
    const resolver = new RecursiveResolver({
        transport: recordingTransport(sent, transport.asTransport()),
        rootHints: TEST_ROOTS,
        use0x20: false,
        qnameMinimization: true
    });
    const r = await resolver.resolve('host.sub.absent.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.NXDOMAIN);
    assert.equal(sent.length, 2);
    assert.equal(sent[1].qname.toLowerCase().replace(/\.$/, ''), 'absent.com');
});
test('RecursiveResolver#qname minimization caches NXDOMAIN for the original qname too', async () => {
    const transport = new MockTransport();
    transport.on('10.0.0.1', 'com', (q) => buildReferral(q, 'com.', ['a.gtld.com.'], [aRec('a.gtld.com.', '10.0.0.2')]));
    transport.on('10.0.0.2', 'absent.com', (q) => buildAnswer(q, [], {
        rcode: RCODE.NXDOMAIN,
        authorities: [soaRec('com', 3600, 60)]
    }));
    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false,
        qnameMinimization: true
    });
    await resolver.resolve('host.absent.com', PacketTypes.A);
    const cached = resolver.cache().get('host.absent.com', PacketTypes.A, PacketClass.IN);
    assert.ok(cached !== null);
    assert.equal(cached.rcode, 'NXDOMAIN');
});
test('RecursiveResolver#qname minimization falls back to full qname when probe gets NODATA', async () => {
    const sent = [];
    const transport = new MockTransport();
    transport.on('10.0.0.1', 'com', (q) => buildReferral(q, 'com.', ['a.gtld.com.'], [aRec('a.gtld.com.', '10.0.0.2')]));
    transport.on('10.0.0.2', 'example.com', (q) => buildAnswer(q, [
        nsRec('example.com', 'a.gtld.com.')
    ], { authorities: [soaRec('example.com', 3600, 60)] }));
    transport.on('10.0.0.2', 'host.example.com', (q) => buildAnswer(q, [
        aRec('host.example.com', '203.0.113.5')
    ]));
    const resolver = new RecursiveResolver({
        transport: recordingTransport(sent, transport.asTransport()),
        rootHints: TEST_ROOTS,
        use0x20: false,
        qnameMinimization: true
    });
    const r = await resolver.resolve('host.example.com', PacketTypes.A);
    assert.equal(r.answers[0].packetType.address, '203.0.113.5');
    assert.equal(sent.length, 3);
    assert.equal(sent[2].qname.toLowerCase().replace(/\.$/, ''), 'host.example.com');
    assert.equal(sent[2].qtype, PacketTypes.A);
});
test('RecursiveResolver#qnameMinimizationLabelsPerStep:2 collapses two-label TLDs', async () => {
    const sent = [];
    const transport = new MockTransport();
    transport.on('10.0.0.1', 'example.com', (q) => buildReferral(q, 'example.com.', ['ns.example.com.'], [aRec('ns.example.com.', '10.0.0.3')]));
    transport.on('10.0.0.3', 'host.example.com', (q) => buildAnswer(q, [
        aRec('host.example.com', '203.0.113.8')
    ]));
    const resolver = new RecursiveResolver({
        transport: recordingTransport(sent, transport.asTransport()),
        rootHints: TEST_ROOTS,
        use0x20: false,
        qnameMinimization: true,
        qnameMinimizationLabelsPerStep: 2
    });
    const r = await resolver.resolve('host.example.com', PacketTypes.A);
    assert.equal(r.answers[0].packetType.address, '203.0.113.8');
    assert.equal(sent[0].qname.toLowerCase().replace(/\.$/, ''), 'example.com');
    assert.equal(sent[0].qtype, PacketTypes.NS);
});
test('RecursiveResolver#qname min permissive fast path: in-bailiwick answer at the probe wins', async () => {
    const sent = [];
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => buildAnswer(q, [
        aRec('host.test', '198.51.100.1')
    ]));
    const resolver = new RecursiveResolver({
        transport: recordingTransport(sent, transport.asTransport()),
        rootHints: TEST_ROOTS,
        use0x20: false,
        qnameMinimization: true
    });
    const r = await resolver.resolve('host.test', PacketTypes.A);
    assert.equal(r.answers[0].packetType.address, '198.51.100.1');
    assert.equal(sent.length, 1);
});
//# sourceMappingURL=recursiveResolver.js.map