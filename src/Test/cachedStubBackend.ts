import assert from 'assert';
import {HostsFile} from '../Lib/HostsFile.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {SOA} from '../Packet/Types/SOA.js';
import {CachedStubBackend} from '../Resolver/CachedStubBackend.js';
import {DnsCache} from '../Resolver/DnsCache.js';
import {RCODE} from '../Resolver/RecursiveResolver.js';
import {StubResolverBackend} from '../Resolver/StubResolver.js';
import {SystemResolver} from '../Resolver/SystemResolver.js';
import {test} from './test.js';

/* helpers ------------------------------------------------------------- */

const buildPositive = (name: string, addr: string, ttl: number = 60): Packet => {
    const p = new Packet();
    p.header.qr = 1;
    p.header.aa = 1;
    p.header.rcode = RCODE.NOERROR;
    p.questions.push(new PacketQuestion(name, PacketTypes.A, PacketClass.IN));
    p.answers.push(new PacketResource(name, new A(addr), PacketClass.IN, ttl));
    return p;
};

const buildNxdomain = (name: string, soaTtl: number = 30): Packet => {
    const p = new Packet();
    p.header.qr = 1;
    p.header.aa = 1;
    p.header.rcode = RCODE.NXDOMAIN;
    p.questions.push(new PacketQuestion(name, PacketTypes.A, PacketClass.IN));
    const soa = new SOA();
    soa.primary = 'ns.example.com';
    soa.admin = 'hostmaster.example.com';
    soa.serial = 1;
    soa.refresh = 7200;
    soa.retry = 3600;
    soa.expiration = 604800;
    soa.minimum = soaTtl;
    p.authorities.push(new PacketResource('example.com', soa, PacketClass.IN, soaTtl));
    return p;
};

const buildNodata = (name: string, soaTtl: number = 30): Packet => {
    const p = buildNxdomain(name, soaTtl);
    p.header.rcode = RCODE.NOERROR;
    return p;
};

const buildServfail = (name: string): Packet => {
    const p = new Packet();
    p.header.qr = 1;
    p.header.rcode = RCODE.SERVFAIL;
    p.questions.push(new PacketQuestion(name, PacketTypes.A, PacketClass.IN));
    return p;
};

const countingBackend = (router: (name: string) => Packet | Promise<Packet>): {
    backend: StubResolverBackend;
    callCount: () => number;
} => {
    let calls = 0;
    const backend: StubResolverBackend = async(name): Promise<Packet> => {
        calls++;
        return router(name);
    };
    return {backend: backend, callCount: (): number => calls};
};

/* positive caching --------------------------------------------------- */

test('CachedStubBackend caches NOERROR answers and short-circuits next call', async() => {
    const {backend, callCount} = countingBackend((name) => buildPositive(name, '192.0.2.1', 300));
    const cached = new CachedStubBackend(backend);

    const r1 = await cached.resolve('www.example.com', PacketTypes.A, PacketClass.IN);
    const r2 = await cached.resolve('www.example.com', PacketTypes.A, PacketClass.IN);

    assert.equal(callCount(), 1, 'second lookup must hit cache');
    assert.equal(r1.header.rcode, RCODE.NOERROR);
    assert.equal(r2.header.rcode, RCODE.NOERROR);
    assert.equal((r2.answers[0].packetType as A).address, '192.0.2.1');
    // Cached response is a fresh Packet — not the same instance.
    assert.notStrictEqual(r1, r2);
});

test('CachedStubBackend keys on (name, type, class) — A and AAAA are independent', async() => {
    const {backend, callCount} = countingBackend((name) => buildPositive(name, '192.0.2.1', 300));
    const cached = new CachedStubBackend(backend);

    await cached.resolve('host.example.com', PacketTypes.A, PacketClass.IN);
    await cached.resolve('host.example.com', PacketTypes.AAAA, PacketClass.IN);

    assert.equal(callCount(), 2, 'different qtype → separate cache slot');
});

test('CachedStubBackend lookup is case-insensitive on name', async() => {
    const {backend, callCount} = countingBackend((name) => buildPositive(name, '192.0.2.1', 300));
    const cached = new CachedStubBackend(backend);

    await cached.resolve('Foo.Example.COM', PacketTypes.A, PacketClass.IN);
    await cached.resolve('foo.example.com', PacketTypes.A, PacketClass.IN);

    assert.equal(callCount(), 1);
});

/* TTL handling ------------------------------------------------------- */

test('CachedStubBackend decrements TTL on serve', async() => {
    let now = 1_700_000_000_000;
    const cache = new DnsCache({now: (): number => now});
    const {backend} = countingBackend((name) => buildPositive(name, '192.0.2.1', 300));
    const cached = new CachedStubBackend(backend, {cache: cache, now: (): number => now});

    await cached.resolve('www.example.com', PacketTypes.A, PacketClass.IN);

    // Advance 30 seconds.
    now += 30_000;

    const r = await cached.resolve('www.example.com', PacketTypes.A, PacketClass.IN);
    assert.equal(r.answers[0].ttl, 270, 'TTL must be decremented by elapsed seconds');
});

test('CachedStubBackend re-queries upstream once TTL expires', async() => {
    let now = 1_700_000_000_000;
    const cache = new DnsCache({now: (): number => now});
    const {backend, callCount} = countingBackend((name) => buildPositive(name, '192.0.2.1', 60));
    const cached = new CachedStubBackend(backend, {cache: cache, now: (): number => now});

    await cached.resolve('www.example.com', PacketTypes.A, PacketClass.IN);
    assert.equal(callCount(), 1);

    // Past expiry, no stale window configured → cache should refuse.
    now += 60_001;

    await cached.resolve('www.example.com', PacketTypes.A, PacketClass.IN);
    assert.equal(callCount(), 2, 'expired entry must trigger fresh upstream query');
});

/* negative caching --------------------------------------------------- */

test('CachedStubBackend caches NXDOMAIN per RFC 2308', async() => {
    const {backend, callCount} = countingBackend((name) => buildNxdomain(name, 30));
    const cached = new CachedStubBackend(backend);

    const r1 = await cached.resolve('missing.example.com', PacketTypes.A, PacketClass.IN);
    const r2 = await cached.resolve('missing.example.com', PacketTypes.A, PacketClass.IN);

    assert.equal(callCount(), 1, 'NXDOMAIN must be cached');
    assert.equal(r1.header.rcode, RCODE.NXDOMAIN);
    assert.equal(r2.header.rcode, RCODE.NXDOMAIN);
    assert.equal(r2.answers.length, 0);
});

test('CachedStubBackend caches NODATA (NOERROR with empty answers)', async() => {
    const {backend, callCount} = countingBackend((name) => buildNodata(name, 30));
    const cached = new CachedStubBackend(backend);

    await cached.resolve('host.example.com', PacketTypes.AAAA, PacketClass.IN);
    const r2 = await cached.resolve('host.example.com', PacketTypes.AAAA, PacketClass.IN);

    assert.equal(callCount(), 1);
    assert.equal(r2.header.rcode, RCODE.NOERROR);
    assert.equal(r2.answers.length, 0);
});

test('CachedStubBackend does NOT cache SERVFAIL by default', async() => {
    const {backend, callCount} = countingBackend((name) => buildServfail(name));
    const cached = new CachedStubBackend(backend);

    await cached.resolve('flaky.example.com', PacketTypes.A, PacketClass.IN);
    await cached.resolve('flaky.example.com', PacketTypes.A, PacketClass.IN);

    assert.equal(callCount(), 2, 'transient failures must not be pinned');
});

test('CachedStubBackend skips caching when isCacheable returns false', async() => {
    const {backend, callCount} = countingBackend((name) => buildPositive(name, '192.0.2.1', 300));
    const cached = new CachedStubBackend(backend, {
        // Veto every response — equivalent to no cache.
        isCacheable: (): boolean => false
    });

    await cached.resolve('www.example.com', PacketTypes.A, PacketClass.IN);
    await cached.resolve('www.example.com', PacketTypes.A, PacketClass.IN);

    assert.equal(callCount(), 2, 'predicate returning false must bypass cache writes');
});

test('CachedStubBackend skips negative cache when SOA is missing (ttl=0)', async() => {
    const {backend, callCount} = countingBackend((name) => {
        const p = buildNxdomain(name, 30);
        p.authorities = [];
        return p;
    });
    const cached = new CachedStubBackend(backend);

    await cached.resolve('a.example.com', PacketTypes.A, PacketClass.IN);
    await cached.resolve('a.example.com', PacketTypes.A, PacketClass.IN);

    assert.equal(callCount(), 2, 'no SOA → no negative TTL → no caching');
});

/* stale-while-revalidate (RFC 8767) ---------------------------------- */

test('CachedStubBackend serves stale + schedules refresh within maxStaleSeconds window', async() => {
    let now = 1_700_000_000_000;
    const cache = new DnsCache({now: (): number => now, maxStaleSeconds: 60});

    let calls = 0;
    let nextAddr = '192.0.2.1';
    const upstream: StubResolverBackend = async(name): Promise<Packet> => {
        calls++;
        return buildPositive(name, nextAddr, 60);
    };

    const cached = new CachedStubBackend(upstream, {cache: cache, now: (): number => now});

    // Prime the cache.
    await cached.resolve('www.example.com', PacketTypes.A, PacketClass.IN);
    assert.equal(calls, 1);

    // Advance past TTL but within stale window.
    now += 90_000;
    nextAddr = '192.0.2.2';

    const r = await cached.resolve('www.example.com', PacketTypes.A, PacketClass.IN);
    // The current caller still got the stale answer, NOT the refreshed one.
    assert.equal((r.answers[0].packetType as A).address, '192.0.2.1');

    // Background refresh was scheduled — wait one tick and verify the
    // cache was updated.
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(calls, 2, 'background refresh must have fired');

    // Next call should serve the fresh value.
    const r2 = await cached.resolve('www.example.com', PacketTypes.A, PacketClass.IN);
    assert.equal((r2.answers[0].packetType as A).address, '192.0.2.2');
    assert.equal(calls, 2, 'fresh value comes from cache, no extra upstream call');
});

test('CachedStubBackend dedupes concurrent stale refreshes', async() => {
    let now = 1_700_000_000_000;
    const cache = new DnsCache({now: (): number => now, maxStaleSeconds: 60});

    let inflight = 0;
    let peakInflight = 0;
    let calls = 0;
    const upstream: StubResolverBackend = async(name): Promise<Packet> => {
        inflight++;
        peakInflight = Math.max(peakInflight, inflight);
        calls++;
        await new Promise<void>((resolve) => setTimeout(resolve, 10));
        inflight--;
        return buildPositive(name, '192.0.2.99', 60);
    };

    const cached = new CachedStubBackend(upstream, {cache: cache, now: (): number => now});

    await cached.resolve('www.example.com', PacketTypes.A, PacketClass.IN);
    assert.equal(calls, 1);

    // Past TTL, within stale window.
    now += 90_000;

    // Fire several stale lookups in parallel — only one background
    // refresh should be in flight.
    await Promise.all([
        cached.resolve('www.example.com', PacketTypes.A, PacketClass.IN),
        cached.resolve('www.example.com', PacketTypes.A, PacketClass.IN),
        cached.resolve('www.example.com', PacketTypes.A, PacketClass.IN)
    ]);

    await new Promise<void>((resolve) => setTimeout(resolve, 30));

    assert.equal(peakInflight, 1, 'only one background refresh at a time');
    assert.equal(calls, 2, '1 prime + 1 refresh');
});

/* construction validation -------------------------------------------- */

test('CachedStubBackend throws on missing upstream', () => {
    assert.throws(
        () => new CachedStubBackend(undefined as unknown as StubResolverBackend),
        /upstream backend is required/
    );
});

test('CachedStubBackend.cache exposes the underlying DnsCache', async() => {
    const {backend} = countingBackend((name) => buildPositive(name, '192.0.2.1', 300));
    const cached = new CachedStubBackend(backend);

    await cached.resolve('www.example.com', PacketTypes.A, PacketClass.IN);
    assert.equal(cached.cache.size(), 1);

    cached.cache.clear();
    assert.equal(cached.cache.size(), 0);
});

test('CachedStubBackend honours external DnsCache instance', async() => {
    const sharedCache = new DnsCache();
    const {backend: b1, callCount: c1} = countingBackend((name) => buildPositive(name, '192.0.2.1', 300));
    const {backend: b2, callCount: c2} = countingBackend((name) => buildPositive(name, '192.0.2.2', 300));

    const cached1 = new CachedStubBackend(b1, {cache: sharedCache});
    const cached2 = new CachedStubBackend(b2, {cache: sharedCache});

    await cached1.resolve('shared.example.com', PacketTypes.A, PacketClass.IN);
    const r = await cached2.resolve('shared.example.com', PacketTypes.A, PacketClass.IN);

    assert.equal(c1(), 1);
    assert.equal(c2(), 0, 'second backend served from shared cache');
    assert.equal((r.answers[0].packetType as A).address, '192.0.2.1');
});

/* SystemResolver wiring --------------------------------------------- */

test('SystemResolver wires cache:true behind HostsFile (hosts still authoritative)', async() => {
    const hosts = HostsFile.parse('10.0.0.5 router.local');

    let upstreamCalls = 0;
    const upstream: StubResolverBackend = async(name): Promise<Packet> => {
        upstreamCalls++;
        return buildPositive(name, '203.0.113.1', 300);
    };

    const resolver = SystemResolver.fromConfig({
        nameservers: ['1.1.1.1'],
        search: [],
        sortlist: [],
        options: {}
    }, {hostsFile: hosts, backend: () => upstream, cache: true});

    assert.ok(resolver.cache !== null, 'cache:true must yield a DnsCache instance');

    // Local hosts hit — must skip cache entirely.
    const r1 = await resolver.resolve('router.local', PacketTypes.A);
    assert.equal((r1.answers[0].packetType as A).address, '10.0.0.5');
    assert.equal(upstreamCalls, 0);
    assert.equal(resolver.cache!.size(), 0, 'hosts-file hits must not consume cache slots');

    // Network query — first miss, then hit.
    await resolver.resolve('public.example.com.', PacketTypes.A);
    await resolver.resolve('public.example.com.', PacketTypes.A);
    assert.equal(upstreamCalls, 1, 'second network query must come from cache');
    assert.equal(resolver.cache!.size(), 1);
});

test('SystemResolver accepts cache: DnsCacheOptions and creates a configured cache', async() => {
    const upstream: StubResolverBackend = async(name): Promise<Packet> => buildPositive(name, '203.0.113.1', 300);

    const resolver = SystemResolver.fromConfig({
        nameservers: ['1.1.1.1'],
        search: [],
        sortlist: [],
        options: {}
    }, {backend: () => upstream, cache: {maxEntries: 7}});

    assert.ok(resolver.cache !== null);

    // Confirm the option made it through — push 8 entries and verify
    // the cap kicked in.
    for (let i = 0; i < 8; i++) {
        await resolver.resolve(`h${i}.example.com.`, PacketTypes.A);
    }
    assert.equal(resolver.cache!.size(), 7);
});

test('SystemResolver accepts an external DnsCache instance', async() => {
    const sharedCache = new DnsCache();
    const upstream: StubResolverBackend = async(name): Promise<Packet> => buildPositive(name, '203.0.113.1', 300);

    const resolver = SystemResolver.fromConfig({
        nameservers: ['1.1.1.1'],
        search: [],
        sortlist: [],
        options: {}
    }, {backend: () => upstream, cache: sharedCache});

    assert.strictEqual(resolver.cache, sharedCache, 'identical instance is returned by .cache');

    await resolver.resolve('host.example.com.', PacketTypes.A);
    assert.equal(sharedCache.size(), 1);
});

test('SystemResolver without cache option exposes null and skips caching', async() => {
    let calls = 0;
    const upstream: StubResolverBackend = async(name): Promise<Packet> => {
        calls++;
        return buildPositive(name, '203.0.113.1', 300);
    };

    const resolver = SystemResolver.fromConfig({
        nameservers: ['1.1.1.1'],
        search: [],
        sortlist: [],
        options: {}
    }, {backend: () => upstream});

    assert.equal(resolver.cache, null);

    await resolver.resolve('host.example.com.', PacketTypes.A);
    await resolver.resolve('host.example.com.', PacketTypes.A);
    assert.equal(calls, 2, 'no cache → every query hits upstream');
});