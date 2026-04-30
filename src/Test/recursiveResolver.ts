import assert from 'assert';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {AAAA} from '../Packet/Types/AAAA.js';
import {CNAME} from '../Packet/Types/CNAME.js';
import {EDNS} from '../Packet/Types/EDNS.js';
import {NS} from '../Packet/Types/NS.js';
import {SOA} from '../Packet/Types/SOA.js';
import {DnsCache} from '../Resolver/DnsCache.js';
import {RCODE, RecursiveResolver, RecursiveResolverTransport} from '../Resolver/RecursiveResolver.js';
import {RootHints} from '../Resolver/RootHints.js';
import {test} from './test.js';

/* Helpers --------------------------------------------------------------- */

const TEST_ROOTS = [{name: 'r.test.', ipv4: '10.0.0.1'}];

const aRec = (name: string, addr: string, ttl: number = 300): PacketResource =>
    new PacketResource(name, new A(addr), PacketClass.IN, ttl);

const aaaaRec = (name: string, addr: string, ttl: number = 300): PacketResource =>
    new PacketResource(name, new AAAA(addr), PacketClass.IN, ttl);

const nsRec = (owner: string, target: string, ttl: number = 300): PacketResource =>
    new PacketResource(owner, new NS(target), PacketClass.IN, ttl);

const cnameRec = (owner: string, target: string, ttl: number = 300): PacketResource =>
    new PacketResource(owner, new CNAME(target), PacketClass.IN, ttl);

const soaRec = (owner: string, ttl: number = 300, minimum: number = 60): PacketResource => {
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

const buildAnswer = (
    query: Packet,
    answers: PacketResource[],
    options: {aa?: boolean; rcode?: number; authorities?: PacketResource[]; additionals?: PacketResource[];} = {}
): Packet => {
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

const buildReferral = (
    query: Packet,
    childZone: string,
    nsList: string[],
    glue: PacketResource[]
): Packet => {
    const r = new Packet();
    r.header.id = query.header.id;
    r.header.qr = 1;
    r.header.aa = 0;
    r.questions = query.questions.slice();
    r.authorities = nsList.map((n) => nsRec(childZone, n));
    r.additionals = glue;
    return r;
};

/**
 * Simple route table — server IP + qname pattern → response builder.
 * Patterns are exact match on lowercase qname; suffix patterns can be
 * expressed as lambdas via `routeFn`.
 */
type RouteHandler = (query: Packet) => Packet;

class MockTransport {

    public readonly routes: Map<string, Map<string, RouteHandler>> = new Map();

    public readonly catchAll: Map<string, RouteHandler> = new Map();

    public callsByServer: Map<string, number> = new Map();

    public on(server: string, qname: string, handler: RouteHandler): this {
        if (!this.routes.has(server)) {
            this.routes.set(server, new Map());
        }

        this.routes.get(server)!.set(MockTransport._norm(qname), handler);
        return this;
    }

    protected static _norm(name: string): string {
        const stripped = name.endsWith('.') && name.length > 1 ? name.slice(0, -1) : name;
        return stripped.toLowerCase();
    }

    public default(server: string, handler: RouteHandler): this {
        this.catchAll.set(server, handler);
        return this;
    }

    public count(server: string): number {
        return this.callsByServer.get(server) ?? 0;
    }

    public asTransport(): RecursiveResolverTransport {
        return async(serverIp: string, _port: number, query: Packet): Promise<Packet> => {
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

/* Tests ----------------------------------------------------------------- */

test('RecursiveResolver#cache hit returns immediately without queries', async() => {
    const cache = new DnsCache();
    cache.set('cached.example.com', PacketTypes.A, PacketClass.IN,
        [aRec('cached.example.com', '192.0.2.99')], 60);

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
    assert.equal((r.answers[0].packetType as A).address, '192.0.2.99');
    // No upstream query issued at all.
    assert.equal(transport.count('10.0.0.1'), 0);
});

test('RecursiveResolver#full chain: root → tld → auth (happy path)', async() => {
    const transport = new MockTransport();

    // Root delegates `.com` to a.gtld.com — in-bailiwick of root, so glue is valid.
    transport.default('10.0.0.1', (q) => buildReferral(
        q,
        'com.',
        ['a.gtld.com.'],
        [aRec('a.gtld.com.', '10.0.0.2')]
    ));

    // gtld delegates `example.com` to ns.example.com — in-bailiwick of `.com`, glue valid.
    transport.default('10.0.0.2', (q) => buildReferral(
        q,
        'example.com.',
        ['ns.example.com.'],
        [aRec('ns.example.com.', '10.0.0.3')]
    ));

    // Auth answers for www.example.com.
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
    assert.equal((r.answers[0].packetType as A).address, '198.51.100.7');

    // Three queries total: root, gtld, auth.
    assert.equal(transport.count('10.0.0.1'), 1);
    assert.equal(transport.count('10.0.0.2'), 1);
    assert.equal(transport.count('10.0.0.3'), 1);
});

test('RecursiveResolver#NXDOMAIN propagates from authoritative response', async() => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'],
        [aRec('auth.test.', '10.0.0.2')]));
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

test('RecursiveResolver#NXDOMAIN is negatively cached (no 2nd upstream)', async() => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'],
        [aRec('auth.test.', '10.0.0.2')]));
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

test('RecursiveResolver#NODATA (NOERROR + empty + SOA) propagates', async() => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'],
        [aRec('auth.test.', '10.0.0.2')]));
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

test('RecursiveResolver#follows CNAME chain', async() => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'],
        [aRec('auth.test.', '10.0.0.2')]));

    // Auth: www → CNAME → real → A
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
    // Chain has the CNAME plus the final A.
    assert.equal(r.answers.length, 2);
    assert.ok(r.answers[0].packetType instanceof CNAME);
    assert.ok(r.answers[1].packetType instanceof A);
    assert.equal((r.answers[1].packetType as A).address, '203.0.113.5');
});

test('RecursiveResolver#CNAME chain in single response is returned directly', async() => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'],
        [aRec('auth.test.', '10.0.0.2')]));

    // Auth answers both records in one response (real-world pattern).
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
    // Only one upstream call to auth — no separate sub-resolve.
    assert.equal(transport.count('10.0.0.2'), 1);
});

test('RecursiveResolver#bailiwick filter strips out-of-zone records from sibling-injection', async() => {
    const transport = new MockTransport();

    // Root → com (clean delegation).
    transport.default('10.0.0.1', (q) => buildReferral(q, 'com.', ['a.gtld.com.'],
        [aRec('a.gtld.com.', '10.0.0.2')]));

    // .com server is malicious: along with the referral for example.com it
    // tries to inject a record for victim.example.org — out of its
    // bailiwick. A correct recursor must drop that on the floor.
    transport.default('10.0.0.2', (q) => buildReferral(q, 'example.com.',
        ['ns.example.com.'],
        [
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
    // The poison should never have entered the cache.
    assert.equal(resolver.cache().get('victim.example.org', PacketTypes.A, PacketClass.IN), null);
    // The legitimate glue did make it.
    const ns = resolver.cache().get('ns.example.com', PacketTypes.A, PacketClass.IN);
    assert.ok(ns);
});

test('RecursiveResolver#0x20 case-mismatch response is rejected', async() => {
    const transport = new MockTransport();

    transport.default('10.0.0.1', (q) => {
        // Server lower-cases the question name (some real servers do).
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
    // 0x20 mismatch escalates the resolver into SERVFAIL because the
    // single root replied with an unverifiable name.
    assert.equal(r.header.rcode, RCODE.SERVFAIL);
});

test('RecursiveResolver#response ID mismatch is rejected', async() => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => {
        const r = new Packet();
        r.header.id = (q.header.id + 1) & 0xFFFF; // off by one
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

test('RecursiveResolver#max-queries budget aborts misbehaving zone', async() => {
    const transport = new MockTransport();

    // Root keeps referring back to itself with a different zone label —
    // resolver should give up.
    let depth = 0;
    transport.default('10.0.0.1', (q) => buildReferral(
        q,
        `${depth++}.example.com.`,
        ['r.test.'],
        [aRec('r.test.', '10.0.0.1')]
    ));

    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false,
        maxQueries: 5
    });

    const r = await resolver.resolve('deep.example.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.SERVFAIL);
});

test('RecursiveResolver#cached CNAME is followed without re-querying', async() => {
    const cache = new DnsCache();
    cache.set('alias.test', PacketTypes.CNAME, PacketClass.IN,
        [cnameRec('alias.test', 'real.test.')], 300);
    cache.set('real.test', PacketTypes.A, PacketClass.IN,
        [aRec('real.test', '198.51.100.99')], 300);

    const transport = new MockTransport();
    const resolver = new RecursiveResolver({
        cache: cache,
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });

    const r = await resolver.resolve('alias.test', PacketTypes.A);
    assert.equal(r.answers.length, 2);
    assert.equal((r.answers[1].packetType as A).address, '198.51.100.99');
    assert.equal(transport.count('10.0.0.1'), 0);
});

test('RecursiveResolver#cache() exposes underlying cache instance', () => {
    const cache = new DnsCache();
    const r = new RecursiveResolver({cache: cache, rootHints: TEST_ROOTS});
    assert.strictEqual(r.cache(), cache);
});

test('RecursiveResolver#constructor primes the cache with root NS', () => {
    const r = new RecursiveResolver({rootHints: TEST_ROOTS});
    const rootNs = r.cache().get('.', PacketTypes.NS, PacketClass.IN);
    assert.ok(rootNs);
    assert.equal(rootNs!.records.length, 1);
});

test('RecursiveResolver#bundled DEFAULT root hints prime when not overridden', () => {
    const r = new RecursiveResolver();
    const rootNs = r.cache().get('.', PacketTypes.NS, PacketClass.IN);
    assert.ok(rootNs);
    assert.equal(rootNs!.records.length, RootHints.DEFAULT.length);
});

test('RecursiveResolver#glueless out-of-bailiwick NS triggers sub-resolution', async() => {
    const transport = new MockTransport();

    // Root delegates `example.com` to ns.other.test — *no glue*.
    const norm = (n: string): string => (n.endsWith('.') && n.length > 1 ? n.slice(0, -1) : n).toLowerCase();
    transport.default('10.0.0.1', (q) => {
        // The root knows about `.test` too (sub-resolution will ask root for
        // the NS chain to resolve ns.other.test).
        if (norm(q.questions[0].name) === 'ns.other.test') {
            return buildReferral(q, 'other.test.', ['gtld.test.'],
                [aRec('gtld.test.', '10.0.0.2')]);
        }

        return buildReferral(q, 'example.com.', ['ns.other.test.'], []);
    });

    // The "other.test" auth resolves the glueless NS's address.
    transport.on('10.0.0.2', 'ns.other.test', (q) => buildAnswer(q, [
        aRec('ns.other.test', '10.0.0.3')
    ]));

    // The actual auth for example.com.
    transport.on('10.0.0.3', 'www.example.com', (q) => buildAnswer(q, [
        aRec('www.example.com', '198.51.100.42')
    ]));

    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });

    const r = await resolver.resolve('www.example.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.NOERROR);
    assert.equal((r.answers[0].packetType as A).address, '198.51.100.42');
});

test('RecursiveResolver#OPT pseudo-records are not cached', async() => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'],
        [aRec('auth.test.', '10.0.0.2')]));
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

test('RecursiveResolver#min TTL of an RRset is what gets cached', async() => {
    const transport = new MockTransport();
    transport.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'],
        [aRec('auth.test.', '10.0.0.2', 600)]));
    transport.on('10.0.0.2', 'multi.example.com', (q) => buildAnswer(q, [
        aRec('multi.example.com', '1.1.1.1', 100),
        aRec('multi.example.com', '2.2.2.2', 50),
        aRec('multi.example.com', '3.3.3.3', 200)
    ]));

    let now = 1_000_000;
    const cache = new DnsCache({now: (): number => now});
    const resolver = new RecursiveResolver({
        cache: cache,
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
    });

    await resolver.resolve('multi.example.com', PacketTypes.A);
    const entry = cache.get('multi.example.com', PacketTypes.A, PacketClass.IN);
    // Min TTL = 50s, expiresAt = now + 50000.
    assert.equal(entry!.expiresAt, 1_000_000 + 50_000);
});

test('RecursiveResolver#TC=1 triggers TCP retry that returns full answer', async() => {
    const udp = new MockTransport();
    const tcp = new MockTransport();

    udp.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'],
        [aRec('auth.test.', '10.0.0.2')]));

    // Auth replies over UDP with TC=1 and an empty answer set — the
    // resolver must reissue the same question over TCP.
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

    // TCP path: full answer (multiple A records, way over 512 bytes in
    // a real scenario; we only need the resolver to follow the retry).
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
    // One UDP query (truncated) plus one TCP query for the same NS.
    assert.equal(udp.count('10.0.0.2'), 1);
    assert.equal(tcp.count('10.0.0.2'), 1);
});

test('RecursiveResolver#TC=1 does not retry when tcpFallback is disabled', async() => {
    const udp = new MockTransport();
    const tcp = new MockTransport();

    udp.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'],
        [aRec('auth.test.', '10.0.0.2')]));

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

    // If the resolver would retry, this would fire — we assert it never does.
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

    // The truncated UDP answer (aa=1, answers present) is taken at face
    // value when fallback is off — useful only for testing the opt-out
    // shape; in production this is why fallback is on by default.
    const r = await resolver.resolve('big.example.com', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.NOERROR);
    assert.equal(udp.count('10.0.0.2'), 1);
    assert.equal(tcp.count('10.0.0.2'), 0);
});

test('RecursiveResolver#TCP transport failure surfaces as SERVFAIL', async() => {
    const udp = new MockTransport();
    const tcp = new MockTransport();

    udp.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'],
        [aRec('auth.test.', '10.0.0.2')]));

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

test('RecursiveResolver#TCP retry counts toward query budget', async() => {
    const udp = new MockTransport();
    const tcp = new MockTransport();

    udp.default('10.0.0.1', (q) => buildReferral(q, 'example.com.', ['auth.test.'],
        [aRec('auth.test.', '10.0.0.2')]));

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

    // Budget = 2: root referral (1) + UDP query (2). The TCP retry
    // should bump us over → SERVFAIL.
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

test('RecursiveResolver#AAAA glue is used when no A is available', async() => {
    const transport = new MockTransport();
    transport.default('::1', (q) => buildAnswer(q, [
        aRec('only-v6.test', '198.51.100.10')
    ]));

    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: [{name: 'r.test.', ipv4: '0.0.0.0', ipv6: '::1'}],
        use0x20: false
    });

    // Force the resolver to use AAAA: pre-empt by deleting the seeded A glue.
    resolver.cache().delete('r.test', PacketTypes.A, PacketClass.IN);

    const r = await resolver.resolve('only-v6.test', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.NOERROR);
    assert.equal(transport.count('::1'), 1);
});

test('RecursiveResolver#outgoing query carries EDNS OPT with default 4096 buffer', async() => {
    const seen: Packet[] = [];
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
    // OPT RR's CLASS field carries the requestor's UDP payload size.
    assert.equal(opt.class, 4096);
});

test('RecursiveResolver#udpPayloadSize override flows into the OPT', async() => {
    const seen: Packet[] = [];
    const transport = new MockTransport();

    transport.default('10.0.0.1', (q) => {
        seen.push(q);
        return buildAnswer(q, [aRec('host.test', '198.51.100.1')]);
    });

    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false,
        udpPayloadSize: 1232 // DNS Flag Day 2020 recommendation
    });

    await resolver.resolve('host.test', PacketTypes.A);
    const opt = seen[0].additionals.find((r) => r.packetType instanceof EDNS);
    assert.ok(opt);
    assert.equal(opt.class, 1232);
});

test('RecursiveResolver#useEdns:false suppresses the OPT RR', async() => {
    const seen: Packet[] = [];
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

test('RecursiveResolver#response OPT is not cached as an RRset', async() => {
    const transport = new MockTransport();

    // Auth replies with both an answer and an OPT in additionals — the
    // OPT advertises the auth's UDP buffer (RFC 6891 §6.1.3) and must
    // be ignored by the cache.
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
    // Sanity: the answer cached, the OPT did not.
    assert.ok(resolver.cache().get('host.test', PacketTypes.A, PacketClass.IN));
    assert.equal(resolver.cache().get('', PacketTypes.EDNS, PacketClass.IN), null);
});

test('RecursiveResolver#DO bit clear when DNSSEC validation is disabled', async() => {
    const seen: Packet[] = [];
    const transport = new MockTransport();

    transport.default('10.0.0.1', (q) => {
        seen.push(q);
        return buildAnswer(q, [aRec('host.test', '198.51.100.1')]);
    });

    const resolver = new RecursiveResolver({
        transport: transport.asTransport(),
        rootHints: TEST_ROOTS,
        use0x20: false
        // dnssec omitted → DO must stay clear
    });

    await resolver.resolve('host.test', PacketTypes.A);
    const opt = seen[0].additionals.find((r) => r.packetType instanceof EDNS);
    assert.ok(opt);
    // eslint-disable-next-line no-bitwise
    assert.equal(opt.ttl & 0x00008000, 0);
});

test('RecursiveResolver#DO bit set when DNSSEC validation is enabled', async() => {
    const seen: Packet[] = [];
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

    // The query goes out before validation runs; we don't need the
    // mock to actually carry RRSIGs to inspect the outgoing OPT.
    await resolver.resolve('host.test', PacketTypes.A);
    const opt = seen[0].additionals.find((r) => r.packetType instanceof EDNS);
    assert.ok(opt);
    // eslint-disable-next-line no-bitwise
    assert.equal(opt.ttl & 0x00008000, 0x00008000);
});

test('RecursiveResolver#smaller server-advertised buffer downgrades the next query', async() => {
    const seen: Packet[] = [];
    const transport = new MockTransport();

    // Auth replies with an OPT advertising a 1232-byte buffer
    // (DNS Flag Day 2020 default — much smaller than our 4096 default).
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

    // First query — outgoing OPT advertises our default 4096.
    await resolver.resolve('host.test', PacketTypes.A);
    let opt = seen[0].additionals.find((r) => r.packetType instanceof EDNS);
    assert.ok(opt);
    assert.equal(opt.class, 4096);

    // Second query to the SAME server should downgrade to 1232 — the
    // server told us in the previous response that it can't ship more.
    await resolver.resolve('other.test', PacketTypes.A);
    opt = seen[1].additionals.find((r) => r.packetType instanceof EDNS);
    assert.ok(opt);
    assert.equal(opt.class, 1232, 'second query must respect the server-advertised buffer');
});

test('RecursiveResolver#larger server-advertised buffer does NOT upgrade past our default', async() => {
    const seen: Packet[] = [];
    const transport = new MockTransport();

    transport.default('10.0.0.1', (q) => {
        seen.push(q);
        const r = buildAnswer(q, [aRec('host.test', '198.51.100.1')]);
        r.additionals.push(EDNS.createResource([], 8192)); // server claims 8KiB
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
    // We respect the server's buffer only when it's *smaller* — never
    // override our own configured ceiling upwards.
    assert.equal(opt.class, 4096);
});

test('RecursiveResolver#missing OPT in response leaves our default unchanged', async() => {
    const seen: Packet[] = [];
    const transport = new MockTransport();

    transport.default('10.0.0.1', (q) => {
        seen.push(q);
        return buildAnswer(q, [aRec('host.test', '198.51.100.1')]);
        // No OPT in response.
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

test('RecursiveResolver#stale cache hit is returned immediately and triggers a background refresh', async() => {
    let now = 1_000_000;
    const cache = new DnsCache({now: (): number => now, maxStaleSeconds: 300});

    // Seed the cache with a record that's already 10s past TTL.
    cache.set('stale.test', PacketTypes.A, PacketClass.IN,
        [aRec('stale.test', '192.0.2.1')], 60);
    now += 70_000;

    const transport = new MockTransport();
    let refreshCalls = 0;
    transport.default('10.0.0.1', (q) => buildReferral(q, 'test.', ['auth.test.'],
        [aRec('auth.test.', '10.0.0.2')]));
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

    // First call — cache hit, returns the *stale* record (10.0.0.2 not consulted yet).
    const r = await resolver.resolve('stale.test', PacketTypes.A);
    assert.equal(r.header.rcode, RCODE.NOERROR);
    assert.equal((r.answers[0].packetType as A).address, '192.0.2.1',
        'caller must see the stale record on the original request');

    // Let the background refresh complete. The mock transport resolves
    // synchronously inside an async wrapper, so a few microtask ticks
    // is enough.
    for (let i = 0; i < 10; i++) {
        // eslint-disable-next-line no-await-in-loop
        await new Promise((resolve) => setImmediate(resolve));
    }

    assert.equal(refreshCalls, 1, 'background refresh must have hit the upstream auth');

    // The cache should now hold the fresh value.
    now += 1_000;
    const fresh = cache.get('stale.test', PacketTypes.A, PacketClass.IN);
    assert.ok(fresh);
    assert.notEqual(fresh!.stale, true);
    assert.equal((fresh!.records[0].packetType as A).address, '192.0.2.99');
});

test('RecursiveResolver#concurrent stale hits dedupe the refresh', async() => {
    let now = 1_000_000;
    const cache = new DnsCache({now: (): number => now, maxStaleSeconds: 300});

    cache.set('stale.test', PacketTypes.A, PacketClass.IN,
        [aRec('stale.test', '192.0.2.1')], 60);
    now += 70_000;

    const transport = new MockTransport();
    let refreshCalls = 0;
    transport.default('10.0.0.1', (q) => buildReferral(q, 'test.', ['auth.test.'],
        [aRec('auth.test.', '10.0.0.2')]));
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

    // Three concurrent calls hitting the same stale entry.
    await Promise.all([
        resolver.resolve('stale.test', PacketTypes.A),
        resolver.resolve('stale.test', PacketTypes.A),
        resolver.resolve('stale.test', PacketTypes.A)
    ]);

    for (let i = 0; i < 10; i++) {
        // eslint-disable-next-line no-await-in-loop
        await new Promise((resolve) => setImmediate(resolve));
    }

    // RFC 8767 §6 — only one refresh should fire even though three
    // callers saw a stale entry.
    assert.equal(refreshCalls, 1);
});

test('RecursiveResolver#stale-while-revalidate disabled by default — expired entries trigger full re-resolution', async() => {
    let now = 1_000_000;
    const cache = new DnsCache({now: (): number => now}); // no maxStaleSeconds

    cache.set('stale.test', PacketTypes.A, PacketClass.IN,
        [aRec('stale.test', '192.0.2.1')], 60);
    now += 70_000;

    const transport = new MockTransport();
    let upstreamCalls = 0;
    transport.default('10.0.0.1', (q) => buildReferral(q, 'test.', ['auth.test.'],
        [aRec('auth.test.', '10.0.0.2')]));
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
    // The expired entry was discarded — caller waits on a fresh resolution.
    assert.equal((r.answers[0].packetType as A).address, '192.0.2.99');
    assert.equal(upstreamCalls, 1);
});