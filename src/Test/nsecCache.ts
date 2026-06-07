import assert from 'assert';
import {Buffer} from 'buffer';
import {Dnssec} from '../Lib/Dnssec.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {NSEC} from '../Packet/Types/NSEC.js';
import {NSEC3} from '../Packet/Types/NSEC3.js';
import {NsecCache} from '../Resolver/NsecCache.js';
import {test} from './test.js';

/* helpers ------------------------------------------------------------ */

const buildNegativePacket = (records: PacketResource[]): Packet => {
    const p = new Packet();
    p.header.qr = 1;
    p.header.rcode = 0;
    p.authorities = records;
    return p;
};

const nsecRecord = (owner: string, next: string, types: number[], ttl: number = 3600): PacketResource => {
    return new PacketResource(owner, new NSEC(next, types), PacketClass.IN, ttl);
};

const nsec3Record = (
    owner: string,
    nextHashHex: string,
    types: number[],
    flags: number = 0,
    ttl: number = 3600,
    salt: string = '',
    iterations: number = 0
): PacketResource => {
    return new PacketResource(
        owner,
        new NSEC3(1, flags, iterations, salt, nextHashHex, types),
        PacketClass.IN,
        ttl
    );
};

/* tests -------------------------------------------------------------- */

test('NsecCache: NODATA via owner-match NSEC (type absent from bitmap)', () => {
    const cache = new NsecCache();
    const packet = buildNegativePacket([
        nsecRecord('host.example.com', 'next.example.com', [PacketTypes.A, PacketTypes.AAAA])
    ]);

    cache.storeFromResponse(packet, 'example.com');

    const proof = cache.proveNegative('host.example.com', PacketTypes.MX);
    assert.ok(proof !== null);
    assert.equal(proof!.kind, 'nodata');
    assert.ok(proof!.ttl > 0);
});

test('NsecCache: no NODATA when type IS in bitmap', () => {
    const cache = new NsecCache();
    cache.storeFromResponse(buildNegativePacket([
        nsecRecord('host.example.com', 'next.example.com', [PacketTypes.A])
    ]), 'example.com');

    assert.equal(cache.proveNegative('host.example.com', PacketTypes.A), null);
});

test('NsecCache: CNAME shadow blocks NODATA synthesis (RFC 4035 §5.4)', () => {
    const cache = new NsecCache();
    cache.storeFromResponse(buildNegativePacket([
        nsecRecord('host.example.com', 'next.example.com', [PacketTypes.CNAME])
    ]), 'example.com');

    assert.equal(cache.proveNegative('host.example.com', PacketTypes.A), null);
});

test('NsecCache: NXDOMAIN requires range cover AND wildcard-absence NSEC', () => {
    const cache = new NsecCache();
    // Range NSEC covers `nonexistent.example.com` (between alpha and zulu).
    cache.storeFromResponse(buildNegativePacket([
        nsecRecord('alpha.example.com', 'zulu.example.com', [PacketTypes.A])
    ]), 'example.com');

    // Without wildcard NSEC, refuse synthesis.
    assert.equal(cache.proveNegative('nonexistent.example.com', PacketTypes.A), null);

    // Add the wildcard-absence NSEC and try again.
    cache.storeFromResponse(buildNegativePacket([
        nsecRecord('example.com', 'a.example.com', [PacketTypes.SOA, PacketTypes.NS])
    ]), 'example.com');

    const proof = cache.proveNegative('nonexistent.example.com', PacketTypes.A);
    assert.ok(proof !== null);
    assert.equal(proof!.kind, 'nxdomain');
});

test('NsecCache: NXDOMAIN refused when wildcard exists at closest encloser', () => {
    const cache = new NsecCache();
    cache.storeFromResponse(buildNegativePacket([
        // Range covers nonexistent.example.com
        nsecRecord('alpha.example.com', 'zulu.example.com', [PacketTypes.A]),
        // Wildcard NSEC says *.example.com exists (own NSEC, not covering)
        nsecRecord('*.example.com', 'alpha.example.com', [PacketTypes.A])
    ]), 'example.com');

    // Wildcard could synthesize for nonexistent.example.com → no synthesis.
    assert.equal(cache.proveNegative('nonexistent.example.com', PacketTypes.A), null);
});

test('NsecCache: entries expire by TTL', () => {
    let clock = 1_000_000;
    const cache = new NsecCache({now: () => clock});

    cache.storeFromResponse(buildNegativePacket([
        nsecRecord('host.example.com', 'next.example.com', [PacketTypes.A], 5)
    ]), 'example.com');

    assert.ok(cache.proveNegative('host.example.com', PacketTypes.MX) !== null);
    clock += 6_000;
    assert.equal(cache.proveNegative('host.example.com', PacketTypes.MX), null);
});

test('NsecCache: NSEC3 NODATA via owner-hash match (type absent)', () => {
    const cache = new NsecCache();
    // Hash example owner so we can store it as an NSEC3.
    const owner = 'host.example.com';
    const zone = 'example.com';
    const hash = Dnssec.nsec3Hash(owner, '', 0);
    const ownerLabel = Dnssec.base32hexEncode(hash).toLowerCase();
    const ownerName = `${ownerLabel}.${zone}`;

    cache.storeFromResponse(buildNegativePacket([
        nsec3Record(ownerName, '00', [PacketTypes.A])
    ]), zone);

    const proof = cache.proveNegative(owner, PacketTypes.MX);
    assert.ok(proof !== null);
    assert.equal(proof!.kind, 'nodata');
});

test('NsecCache: NSEC3 opt-out skipped for DS / NS queries (RFC 5155 §6)', () => {
    const cache = new NsecCache();
    const owner = 'host.example.com';
    const zone = 'example.com';
    const hash = Dnssec.nsec3Hash(owner, '', 0);
    const ownerLabel = Dnssec.base32hexEncode(hash).toLowerCase();
    const ownerName = `${ownerLabel}.${zone}`;

    cache.storeFromResponse(buildNegativePacket([
        // Opt-out flag = 0x01; bitmap has neither DS nor NS.
        nsec3Record(ownerName, '00', [PacketTypes.A], 0x01)
    ]), zone);

    // Non-delegation types — synthesis OK.
    assert.ok(cache.proveNegative(owner, PacketTypes.MX) !== null);
    // DS / NS — opt-out means insufficient proof, refuse.
    assert.equal(cache.proveNegative(owner, PacketTypes.DS), null);
    assert.equal(cache.proveNegative(owner, PacketTypes.NS), null);
});

test('NsecCache: forgetZone drops all entries for that zone', () => {
    const cache = new NsecCache();
    cache.storeFromResponse(buildNegativePacket([
        nsecRecord('host.example.com', 'next.example.com', [PacketTypes.A])
    ]), 'example.com');
    cache.storeFromResponse(buildNegativePacket([
        nsecRecord('host.other.com', 'next.other.com', [PacketTypes.A])
    ]), 'other.com');

    cache.forgetZone('example.com');

    assert.equal(cache.proveNegative('host.example.com', PacketTypes.MX), null);
    assert.ok(cache.proveNegative('host.other.com', PacketTypes.MX) !== null);
});

test('NsecCache: clear wipes everything', () => {
    const cache = new NsecCache();
    cache.storeFromResponse(buildNegativePacket([
        nsecRecord('host.example.com', 'next.example.com', [PacketTypes.A])
    ]), 'example.com');

    cache.clear();
    assert.equal(cache.size(), 0);
    assert.equal(cache.proveNegative('host.example.com', PacketTypes.MX), null);
});

test('NsecCache: replacing an existing owner overwrites in place (no duplicate)', () => {
    const cache = new NsecCache();
    cache.storeFromResponse(buildNegativePacket([
        nsecRecord('host.example.com', 'next.example.com', [PacketTypes.A])
    ]), 'example.com');
    const before = cache.size();

    cache.storeFromResponse(buildNegativePacket([
        nsecRecord('host.example.com', 'next.example.com', [PacketTypes.A, PacketTypes.AAAA])
    ]), 'example.com');

    assert.equal(cache.size(), before);
    // Now A is in the bitmap — NODATA synthesis for A should fail.
    assert.equal(cache.proveNegative('host.example.com', PacketTypes.A), null);
});

test('NsecCache: maxEntries FIFO-evicts the oldest entry', () => {
    const cache = new NsecCache({maxEntries: 2});
    cache.storeFromResponse(buildNegativePacket([
        nsecRecord('aaa.example.com', 'bbb.example.com', [PacketTypes.A])
    ]), 'example.com');
    cache.storeFromResponse(buildNegativePacket([
        nsecRecord('ccc.example.com', 'ddd.example.com', [PacketTypes.A])
    ]), 'example.com');
    cache.storeFromResponse(buildNegativePacket([
        nsecRecord('eee.example.com', 'fff.example.com', [PacketTypes.A])
    ]), 'example.com');

    assert.ok(cache.size() <= 2);
    // The first owner has been evicted — NODATA on its qname must fail.
    assert.equal(cache.proveNegative('aaa.example.com', PacketTypes.MX), null);
});

test('NsecCache: case-insensitive owner matching', () => {
    const cache = new NsecCache();
    cache.storeFromResponse(buildNegativePacket([
        nsecRecord('Host.EXAMPLE.com', 'next.example.com', [PacketTypes.A])
    ]), 'example.com');

    assert.ok(cache.proveNegative('host.example.com', PacketTypes.MX) !== null);
    assert.ok(cache.proveNegative('HOST.EXAMPLE.COM', PacketTypes.MX) !== null);
});

test('NsecCache: NSEC3 params are captured from the first NSEC3 seen', () => {
    const cache = new NsecCache();
    const zone = 'example.com';
    const hash = Dnssec.nsec3Hash('host.example.com', 'aabb', 12);
    const ownerLabel = Dnssec.base32hexEncode(hash).toLowerCase();
    const ownerName = `${ownerLabel}.${zone}`;

    cache.storeFromResponse(buildNegativePacket([
        nsec3Record(ownerName, '00', [PacketTypes.A], 0, 3600, 'aabb', 12)
    ]), zone);

    const params = cache.getNsec3Params(zone);
    assert.ok(params !== null);
    assert.equal(params!.salt, 'aabb');
    assert.equal(params!.iterations, 12);
});

test('NsecCache.proveNegative: returns null for zone not present in cache', () => {
    const cache = new NsecCache();
    assert.equal(cache.proveNegative('host.unseen.com', PacketTypes.A), null);
});

test('NsecCache: trailing-dot tolerant on qname lookup', () => {
    const cache = new NsecCache();
    cache.storeFromResponse(buildNegativePacket([
        nsecRecord('host.example.com.', 'next.example.com.', [PacketTypes.A])
    ]), 'example.com.');

    assert.ok(cache.proveNegative('host.example.com', PacketTypes.MX) !== null);
    assert.ok(cache.proveNegative('host.example.com.', PacketTypes.MX) !== null);
});

test('NsecCache: nxdomain TTL is min of cover and wildcard NSEC TTLs', () => {
    const cache = new NsecCache();
    cache.storeFromResponse(buildNegativePacket([
        nsecRecord('alpha.example.com', 'zulu.example.com', [PacketTypes.A], 500),
        nsecRecord('example.com', 'a.example.com', [PacketTypes.SOA], 200)
    ]), 'example.com');

    const proof = cache.proveNegative('nonexistent.example.com', PacketTypes.A);
    assert.ok(proof !== null);
    assert.equal(proof!.kind, 'nxdomain');
    assert.ok(proof!.ttl <= 200, 'TTL clamped to the smaller NSEC TTL');
});