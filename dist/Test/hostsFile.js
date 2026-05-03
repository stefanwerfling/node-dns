import assert from 'assert';
import { HostsFile } from '../Lib/HostsFile.js';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { test } from './test.js';
const SAMPLE = `
# Standard loopback entries
127.0.0.1   localhost loopback
::1         localhost ip6-localhost ip6-loopback

# Project-local overrides
192.168.1.5  printer printer.local Printer.LOCAL
2001:db8::1  ipv6-only.example
malformed
1.2.3.4
not-an-ip   foo.bar
1.2.3.4 spaced.example   # trailing comment
`;
test('HostsFile.parse skips comments, empty lines, and malformed entries', () => {
    const hosts = HostsFile.parse(SAMPLE);
    const entries = hosts.entries;
    assert.strictEqual(entries.length, 5);
    assert.strictEqual(entries[0].address, '127.0.0.1');
    assert.deepStrictEqual(entries[0].names, ['localhost', 'loopback']);
    assert.strictEqual(entries[0].family, 'ipv4');
    assert.strictEqual(entries[1].family, 'ipv6');
    assert.strictEqual(entries[1].address, '::1');
    assert.deepStrictEqual(entries[2].names, ['printer', 'printer.local', 'printer.local'], 'names lowercased — Printer.LOCAL collapses with printer.local at lookup');
});
test('HostsFile#lookup returns A records for IPv4 entries', () => {
    const hosts = HostsFile.parse(SAMPLE);
    const result = hosts.lookup('printer', PacketTypes.A);
    assert.strictEqual(result.kind, 'match');
    if (result.kind !== 'match') {
        return;
    }
    assert.strictEqual(result.records.length, 1);
    assert.strictEqual(result.records[0].packetType.address, '192.168.1.5');
    assert.strictEqual(result.records[0].name, 'printer');
});
test('HostsFile#lookup returns AAAA records for IPv6 entries', () => {
    const hosts = HostsFile.parse(SAMPLE);
    const result = hosts.lookup('ipv6-only.example', PacketTypes.AAAA);
    assert.strictEqual(result.kind, 'match');
    if (result.kind !== 'match') {
        return;
    }
    assert.strictEqual(result.records[0].packetType.address, '2001:db8::1');
});
test('HostsFile#lookup is case-insensitive and trailing-dot tolerant', () => {
    const hosts = HostsFile.parse(SAMPLE);
    const lower = hosts.lookup('printer.local', PacketTypes.A);
    const upper = hosts.lookup('PRINTER.LOCAL', PacketTypes.A);
    const dotted = hosts.lookup('printer.local.', PacketTypes.A);
    assert.strictEqual(lower.kind, 'match');
    assert.strictEqual(upper.kind, 'match');
    assert.strictEqual(dotted.kind, 'match');
});
test('HostsFile#lookup returns both A entries when a name has multiple v4 IPs', () => {
    const hosts = HostsFile.parse(`
        10.0.0.1 web
        10.0.0.2 web
    `);
    const result = hosts.lookup('web', PacketTypes.A);
    assert.strictEqual(result.kind, 'match');
    if (result.kind !== 'match') {
        return;
    }
    assert.strictEqual(result.records.length, 2);
    assert.strictEqual(result.records[0].packetType.address, '10.0.0.1');
    assert.strictEqual(result.records[1].packetType.address, '10.0.0.2');
});
test('HostsFile#lookup returns NODATA when name exists but type does not match', () => {
    const hosts = HostsFile.parse('192.168.1.5 printer');
    const result = hosts.lookup('printer', PacketTypes.AAAA);
    assert.strictEqual(result.kind, 'nodata', 'name in file but no IPv6 → NODATA, not miss');
});
test('HostsFile#lookup returns miss when name not in file', () => {
    const hosts = HostsFile.parse(SAMPLE);
    const result = hosts.lookup('not-in-hosts', PacketTypes.A);
    assert.strictEqual(result.kind, 'miss');
});
test('HostsFile#lookup honours TTL option', () => {
    const hosts = HostsFile.parse('192.168.1.5 printer', { ttl: 600 });
    const result = hosts.lookup('printer', PacketTypes.A);
    assert.strictEqual(result.kind, 'match');
    if (result.kind === 'match') {
        assert.strictEqual(result.records[0].ttl, 600);
    }
});
test('HostsFile#asResolverBackend serves match without consulting fallback', async () => {
    const hosts = HostsFile.parse('10.0.0.1 host.local');
    let fallbackCalls = 0;
    const fallback = async () => {
        fallbackCalls++;
        const p = new Packet();
        p.header.qr = 1;
        return p;
    };
    const backend = hosts.asResolverBackend(fallback);
    const response = await backend('host.local', PacketTypes.A, PacketClass.IN);
    assert.strictEqual(response.header.aa, 1, 'synthesized response is authoritative');
    assert.strictEqual(response.answers.length, 1);
    assert.strictEqual(response.answers[0].packetType.address, '10.0.0.1');
    assert.strictEqual(fallbackCalls, 0, 'fallback must not be invoked when file has the name');
});
test('HostsFile#asResolverBackend returns NODATA without falling through', async () => {
    const hosts = HostsFile.parse('10.0.0.1 host.local');
    let fallbackCalls = 0;
    const fallback = async () => {
        fallbackCalls++;
        const p = new Packet();
        return p;
    };
    const backend = hosts.asResolverBackend(fallback);
    const response = await backend('host.local', PacketTypes.AAAA, PacketClass.IN);
    assert.strictEqual(response.header.qr, 1);
    assert.strictEqual(response.answers.length, 0, 'NODATA = NOERROR with empty answers');
    assert.strictEqual(response.header.rcode, 0);
    assert.strictEqual(fallbackCalls, 0, 'NODATA must not fall through to DNS');
});
test('HostsFile#asResolverBackend falls through on miss', async () => {
    const hosts = HostsFile.parse('10.0.0.1 host.local');
    let fallbackCalls = 0;
    let receivedName = '';
    const fallback = async (name) => {
        fallbackCalls++;
        receivedName = name;
        const p = new Packet();
        p.header.qr = 1;
        return p;
    };
    const backend = hosts.asResolverBackend(fallback);
    await backend('not-in-hosts', PacketTypes.A, PacketClass.IN);
    assert.strictEqual(fallbackCalls, 1);
    assert.strictEqual(receivedName, 'not-in-hosts');
});
test('HostsFile#merge stacks tables, earlier entries win on name collision', () => {
    const system = HostsFile.parse('1.1.1.1 web');
    const local = HostsFile.parse(`
        2.2.2.2 web
        3.3.3.3 lab
    `);
    const merged = system.merge(local);
    const resWeb = merged.lookup('web', PacketTypes.A);
    assert.strictEqual(resWeb.kind, 'match');
    if (resWeb.kind === 'match') {
        assert.strictEqual(resWeb.records.length, 2);
        assert.strictEqual(resWeb.records[0].packetType.address, '1.1.1.1');
        assert.strictEqual(resWeb.records[1].packetType.address, '2.2.2.2');
    }
    const resLab = merged.lookup('lab', PacketTypes.A);
    assert.strictEqual(resLab.kind, 'match');
});
test('HostsFile.parse handles trailing-comment lines', () => {
    const hosts = HostsFile.parse(SAMPLE);
    const result = hosts.lookup('spaced.example', PacketTypes.A);
    assert.strictEqual(result.kind, 'match');
    if (result.kind === 'match') {
        assert.strictEqual(result.records[0].packetType.address, '1.2.3.4');
    }
});
//# sourceMappingURL=hostsFile.js.map