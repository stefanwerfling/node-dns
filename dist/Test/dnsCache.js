import assert from 'assert';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { AAAA } from '../Packet/Types/AAAA.js';
import { DnsCache } from '../Resolver/DnsCache.js';
import { test } from './test.js';
const a = (name, addr, ttl = 3600) => new PacketResource(name, new A(addr), PacketClass.IN, ttl);
test('DnsCache#set/get round-trip on positive entry', () => {
    const cache = new DnsCache();
    cache.set('www.example.com', PacketTypes.A, PacketClass.IN, [a('www.example.com', '192.0.2.1')], 60);
    const got = cache.get('www.example.com', PacketTypes.A, PacketClass.IN);
    assert.ok(got);
    assert.equal(got.rcode, 'NOERROR');
    assert.equal(got.records.length, 1);
    assert.equal(got.records[0].packetType.address, '192.0.2.1');
});
test('DnsCache#get returns null on miss', () => {
    const cache = new DnsCache();
    assert.equal(cache.get('absent.example.com', PacketTypes.A, PacketClass.IN), null);
});
test('DnsCache#name lookup is case-insensitive', () => {
    const cache = new DnsCache();
    cache.set('WWW.Example.COM', PacketTypes.A, PacketClass.IN, [a('www.example.com', '192.0.2.1')], 60);
    assert.ok(cache.get('www.example.com', PacketTypes.A, PacketClass.IN));
    assert.ok(cache.get('WWW.EXAMPLE.COM', PacketTypes.A, PacketClass.IN));
});
test('DnsCache#trailing dot is normalized', () => {
    const cache = new DnsCache();
    cache.set('example.com.', PacketTypes.A, PacketClass.IN, [a('example.com', '192.0.2.1')], 60);
    assert.ok(cache.get('example.com', PacketTypes.A, PacketClass.IN));
});
test('DnsCache#different types are separate entries', () => {
    const cache = new DnsCache();
    cache.set('host.example.com', PacketTypes.A, PacketClass.IN, [a('host.example.com', '192.0.2.1')], 60);
    cache.set('host.example.com', PacketTypes.AAAA, PacketClass.IN, [new PacketResource('host.example.com', new AAAA('2001:db8::1'), PacketClass.IN, 60)], 60);
    assert.equal(cache.size(), 2);
    assert.ok(cache.get('host.example.com', PacketTypes.A, PacketClass.IN));
    assert.ok(cache.get('host.example.com', PacketTypes.AAAA, PacketClass.IN));
});
test('DnsCache#expired entries return null and are evicted', () => {
    let now = 1_000_000;
    const cache = new DnsCache({ now: () => now });
    cache.set('www.example.com', PacketTypes.A, PacketClass.IN, [a('www.example.com', '192.0.2.1')], 60);
    assert.equal(cache.size(), 1);
    now += 60_000 + 1;
    assert.equal(cache.get('www.example.com', PacketTypes.A, PacketClass.IN), null);
    assert.equal(cache.size(), 0);
});
test('DnsCache#set with maxTtl clamps long TTLs', () => {
    const cache = new DnsCache({ maxTtlSeconds: 60, now: () => 0 });
    cache.set('www.example.com', PacketTypes.A, PacketClass.IN, [a('www.example.com', '192.0.2.1')], 86_400);
    const got = cache.get('www.example.com', PacketTypes.A, PacketClass.IN);
    assert.equal(got.expiresAt, 60_000);
});
test('DnsCache#set with minTtl floors short TTLs', () => {
    const cache = new DnsCache({ minTtlSeconds: 5, now: () => 0 });
    cache.set('www.example.com', PacketTypes.A, PacketClass.IN, [a('www.example.com', '192.0.2.1')], 0);
    const got = cache.get('www.example.com', PacketTypes.A, PacketClass.IN);
    assert.equal(got.expiresAt, 5_000);
});
test('DnsCache#setNegative stores NXDOMAIN with empty records', () => {
    const cache = new DnsCache();
    cache.setNegative('absent.example.com', PacketTypes.A, PacketClass.IN, 'NXDOMAIN', 30);
    const got = cache.get('absent.example.com', PacketTypes.A, PacketClass.IN);
    assert.equal(got.rcode, 'NXDOMAIN');
    assert.equal(got.records.length, 0);
});
test('DnsCache#setNegative distinguishes NODATA from NXDOMAIN', () => {
    const cache = new DnsCache();
    cache.setNegative('host.example.com', PacketTypes.MX, PacketClass.IN, 'NODATA', 30);
    const got = cache.get('host.example.com', PacketTypes.MX, PacketClass.IN);
    assert.equal(got.rcode, 'NODATA');
});
test('DnsCache#delete removes an entry', () => {
    const cache = new DnsCache();
    cache.set('www.example.com', PacketTypes.A, PacketClass.IN, [a('www.example.com', '192.0.2.1')], 60);
    cache.delete('www.example.com', PacketTypes.A, PacketClass.IN);
    assert.equal(cache.get('www.example.com', PacketTypes.A, PacketClass.IN), null);
});
test('DnsCache#clear empties the cache', () => {
    const cache = new DnsCache();
    cache.set('a.example.com', PacketTypes.A, PacketClass.IN, [a('a.example.com', '192.0.2.1')], 60);
    cache.set('b.example.com', PacketTypes.A, PacketClass.IN, [a('b.example.com', '192.0.2.2')], 60);
    cache.clear();
    assert.equal(cache.size(), 0);
});
test('DnsCache#LRU eviction drops the least recently used', () => {
    const cache = new DnsCache({ maxEntries: 2 });
    cache.set('a.example.com', PacketTypes.A, PacketClass.IN, [a('a.example.com', '1.1.1.1')], 60);
    cache.set('b.example.com', PacketTypes.A, PacketClass.IN, [a('b.example.com', '2.2.2.2')], 60);
    cache.get('a.example.com', PacketTypes.A, PacketClass.IN);
    cache.set('c.example.com', PacketTypes.A, PacketClass.IN, [a('c.example.com', '3.3.3.3')], 60);
    assert.equal(cache.size(), 2);
    assert.ok(cache.get('a.example.com', PacketTypes.A, PacketClass.IN));
    assert.equal(cache.get('b.example.com', PacketTypes.A, PacketClass.IN), null);
    assert.ok(cache.get('c.example.com', PacketTypes.A, PacketClass.IN));
});
test('DnsCache#replacing an entry resets its expiry', () => {
    let now = 1_000_000;
    const cache = new DnsCache({ now: () => now });
    cache.set('www.example.com', PacketTypes.A, PacketClass.IN, [a('www.example.com', '192.0.2.1')], 60);
    now += 30_000;
    cache.set('www.example.com', PacketTypes.A, PacketClass.IN, [a('www.example.com', '192.0.2.2')], 60);
    now = 1_080_000;
    const got = cache.get('www.example.com', PacketTypes.A, PacketClass.IN);
    assert.ok(got);
    assert.equal(got.records[0].packetType.address, '192.0.2.2');
});
test('DnsCache#stored records are detached from the input array', () => {
    const cache = new DnsCache();
    const records = [a('www.example.com', '192.0.2.1')];
    cache.set('www.example.com', PacketTypes.A, PacketClass.IN, records, 60);
    records.push(a('www.example.com', '192.0.2.2'));
    const got = cache.get('www.example.com', PacketTypes.A, PacketClass.IN);
    assert.equal(got.records.length, 1);
});
test('DnsCache#serve-stale off by default — expired entries return null', () => {
    let now = 1_000_000;
    const cache = new DnsCache({ now: () => now });
    cache.set('www.example.com', PacketTypes.A, PacketClass.IN, [a('www.example.com', '192.0.2.1')], 60);
    now += 70_000;
    assert.equal(cache.get('www.example.com', PacketTypes.A, PacketClass.IN), null);
});
test('DnsCache#serve-stale returns expired entries with stale=true within the window', () => {
    let now = 1_000_000;
    const cache = new DnsCache({ now: () => now, maxStaleSeconds: 300 });
    cache.set('www.example.com', PacketTypes.A, PacketClass.IN, [a('www.example.com', '192.0.2.1')], 60);
    now += 70_000;
    const got = cache.get('www.example.com', PacketTypes.A, PacketClass.IN);
    assert.ok(got);
    assert.equal(got.stale, true);
    assert.equal(got.records[0].packetType.address, '192.0.2.1');
});
test('DnsCache#serve-stale evicts past the max-stale window', () => {
    let now = 1_000_000;
    const cache = new DnsCache({ now: () => now, maxStaleSeconds: 300 });
    cache.set('www.example.com', PacketTypes.A, PacketClass.IN, [a('www.example.com', '192.0.2.1')], 60);
    now += 400_000;
    assert.equal(cache.get('www.example.com', PacketTypes.A, PacketClass.IN), null);
});
test('DnsCache#serve-stale leaves fresh entries untagged', () => {
    let now = 1_000_000;
    const cache = new DnsCache({ now: () => now, maxStaleSeconds: 300 });
    cache.set('www.example.com', PacketTypes.A, PacketClass.IN, [a('www.example.com', '192.0.2.1')], 60);
    now += 30_000;
    const got = cache.get('www.example.com', PacketTypes.A, PacketClass.IN);
    assert.ok(got);
    assert.notEqual(got.stale, true, 'fresh entries must not be flagged stale');
});
test('DnsCache#serve-stale does not mutate the stored entry', () => {
    let now = 1_000_000;
    const cache = new DnsCache({ now: () => now, maxStaleSeconds: 300 });
    cache.set('www.example.com', PacketTypes.A, PacketClass.IN, [a('www.example.com', '192.0.2.1')], 60);
    now += 70_000;
    const stale = cache.get('www.example.com', PacketTypes.A, PacketClass.IN);
    assert.ok(stale);
    assert.equal(stale.stale, true);
    cache.set('www.example.com', PacketTypes.A, PacketClass.IN, [a('www.example.com', '192.0.2.2')], 60);
    const fresh = cache.get('www.example.com', PacketTypes.A, PacketClass.IN);
    assert.ok(fresh);
    assert.notEqual(fresh.stale, true, 'a re-set entry must not inherit a stale flag from earlier reads');
});
//# sourceMappingURL=dnsCache.js.map