import assert from 'assert';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {AAAA} from '../Packet/Types/AAAA.js';
import {NS} from '../Packet/Types/NS.js';
import {DnsCache} from '../Resolver/DnsCache.js';
import {RootHints} from '../Resolver/RootHints.js';
import {test} from './test.js';

test('RootHints#DEFAULT lists 13 root servers (a-m)', () => {
    assert.equal(RootHints.DEFAULT.length, 13);
    const letters = RootHints.DEFAULT.map((s) => s.name[0]).sort();
    assert.deepEqual(letters, ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm']);
});

test('RootHints#DEFAULT every entry has both IPv4 and IPv6', () => {
    for (const s of RootHints.DEFAULT) {
        assert.ok(/^\d+\.\d+\.\d+\.\d+$/u.test(s.ipv4), `bad IPv4 for ${s.name}: ${s.ipv4}`);
        assert.ok(s.ipv6 && s.ipv6.includes(':'), `bad IPv6 for ${s.name}: ${String(s.ipv6)}`);
    }
});

test('RootHints#toRecords produces NS at root and A+AAAA glue', () => {
    const records = RootHints.toRecords();

    assert.equal(records.ns.length, 13);
    for (const r of records.ns) {
        assert.equal(r.name, '.');
        assert.equal(r.packetType.type, PacketTypes.NS);
    }

    // 13 v4 + 13 v6 = 26 glue records.
    assert.equal(records.glue.length, 26);
    const v4Count = records.glue.filter((r) => r.packetType instanceof A).length;
    const v6Count = records.glue.filter((r) => r.packetType instanceof AAAA).length;
    assert.equal(v4Count, 13);
    assert.equal(v6Count, 13);
});

test('RootHints#toRecords honours custom servers list (v4-only entry has no AAAA)', () => {
    const records = RootHints.toRecords([
        {name: 'a.test.', ipv4: '10.0.0.1'},
        {name: 'b.test.', ipv4: '10.0.0.2', ipv6: '::2'}
    ]);

    assert.equal(records.ns.length, 2);
    // a.test only has v4; b.test has both. Total 3 glue records.
    assert.equal(records.glue.length, 3);
});

test('RootHints#seedCache populates root NS and glue', () => {
    const cache = new DnsCache();
    RootHints.seedCache(cache);

    const rootNs = cache.get('.', PacketTypes.NS, PacketClass.IN);
    assert.ok(rootNs);
    assert.equal(rootNs!.records.length, 13);

    const aRoot = cache.get('a.root-servers.net.', PacketTypes.A, PacketClass.IN);
    assert.ok(aRoot);
    assert.equal((aRoot!.records[0].packetType as A).address, '198.41.0.4');

    const mRoot = cache.get('m.root-servers.net', PacketTypes.AAAA, PacketClass.IN);
    assert.ok(mRoot);
    assert.equal((mRoot!.records[0].packetType as AAAA).address, '2001:dc3::35');
});

test('RootHints#seedCache groups multiple addresses per server name correctly', () => {
    const cache = new DnsCache();
    RootHints.seedCache(cache, [
        {name: 'a.test.', ipv4: '10.0.0.1', ipv6: '::1'},
        {name: 'a.test.', ipv4: '10.0.0.2'}
    ]);

    const a = cache.get('a.test', PacketTypes.A, PacketClass.IN);
    assert.equal(a!.records.length, 2);
    const aaaa = cache.get('a.test', PacketTypes.AAAA, PacketClass.IN);
    assert.equal(aaaa!.records.length, 1);
});

test('RootHints#fromNamedRoot parses canonical zone-hints subset', () => {
    const text = `
;       This file holds the information on root name servers needed to
;       initialize cache of Internet domain name servers.
;
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
.                        3600000      NS    B.ROOT-SERVERS.NET.
B.ROOT-SERVERS.NET.      3600000      A     170.247.170.2
B.ROOT-SERVERS.NET.      3600000      AAAA  2801:1b8:10::b
`;

    const servers = RootHints.fromNamedRoot(text);

    assert.equal(servers.length, 2);
    assert.deepEqual(servers[0], {
        name: 'A.ROOT-SERVERS.NET.',
        ipv4: '198.41.0.4',
        ipv6: '2001:503:ba3e::2:30'
    });
    assert.equal(servers[1].name, 'B.ROOT-SERVERS.NET.');
});

test('RootHints#fromNamedRoot throws when an NS has no A glue', () => {
    const text = `
.                NS  ghost.root-servers.net.
.                NS  a.root-servers.net.
A.ROOT-SERVERS.NET.  A  198.41.0.4
`;

    assert.throws(() => RootHints.fromNamedRoot(text), /no A glue/u);
});

test('RootHints#fromNamedRoot tolerates owner without trailing dot', () => {
    const text = `
.                NS  a.test
a.test           A   10.0.0.1
`;
    const servers = RootHints.fromNamedRoot(text);
    assert.equal(servers[0].name, 'a.test.');
});

test('RootHints#NS records have correct type and target', () => {
    const records = RootHints.toRecords([{name: 'a.test.', ipv4: '10.0.0.1'}]);
    const ns = records.ns[0].packetType as NS;
    assert.equal(ns.ns, 'a.test.');
});