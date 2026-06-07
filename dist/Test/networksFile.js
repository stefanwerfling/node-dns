import assert from 'assert';
import { Buffer } from 'buffer';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { NetworksFile } from '../Lib/NetworksFile.js';
import { test } from './test.js';
const SAMPLE = `
# A typical /etc/networks
default        0.0.0.0
loopback       127.0.0.0
link-local     169.254
mynet          192.168.1     home  lan  # trailing comment
broken-line
not-an-address foo.bar.baz
`.trim();
test('NetworksFile.parse: skips comments and blank lines', () => {
    const file = NetworksFile.parse(SAMPLE);
    const names = file.entries.map((e) => e.name);
    assert.deepEqual(names, ['default', 'loopback', 'link-local', 'mynet']);
});
test('NetworksFile.parse: expands abbreviated addresses to full dotted-quad', () => {
    const file = NetworksFile.parse(SAMPLE);
    assert.equal(file.lookupByName('loopback').address, '127.0.0.0');
    assert.equal(file.lookupByName('link-local').address, '169.254.0.0');
    assert.equal(file.lookupByName('mynet').address, '192.168.1.0');
    assert.equal(file.lookupByName('default').address, '0.0.0.0');
});
test('NetworksFile.parse: captures aliases case-folded', () => {
    const file = NetworksFile.parse('mynet 192.168.1 Home LAN');
    const entry = file.lookupByName('mynet');
    assert.ok(entry !== null);
    assert.deepEqual(entry.aliases, ['home', 'lan']);
});
test('NetworksFile.parse: skips lines with malformed addresses', () => {
    const file = NetworksFile.parse('bad 256.0.0.0\nworse 1.2.3.4.5\nfine 10.0.0.0');
    const names = file.entries.map((e) => e.name);
    assert.deepEqual(names, ['fine']);
});
test('NetworksFile#lookupByName: case-insensitive + alias-aware', () => {
    const file = NetworksFile.parse('mynet 192.168.1 lan');
    const direct = file.lookupByName('MYNET');
    const viaAlias = file.lookupByName('LAN');
    assert.ok(direct !== null);
    assert.equal(direct, viaAlias);
});
test('NetworksFile#lookupByAddress: accepts dotted-quad string + Buffer', () => {
    const file = NetworksFile.parse('loopback 127.0.0.0');
    const viaStr = file.lookupByAddress('127.0.0.0');
    const viaBuffer = file.lookupByAddress(Buffer.from([127, 0, 0, 0]));
    const viaShort = file.lookupByAddress('127');
    assert.ok(viaStr !== null);
    assert.equal(viaStr, viaBuffer);
    assert.equal(viaStr, viaShort, 'short form normalized for lookup');
});
test('NetworksFile#lookupByAddress: returns null for non-matching + malformed addresses', () => {
    const file = NetworksFile.parse('loopback 127.0.0.0');
    assert.equal(file.lookupByAddress('10.0.0.0'), null);
    assert.equal(file.lookupByAddress('not.an.ip'), null);
    assert.equal(file.lookupByAddress(Buffer.from([1, 2, 3])), null, 'wrong-length buffer rejected');
});
test('NetworksFile.fromFile: returns empty instance on missing file (glibc tolerance)', () => {
    const missing = path.join(os.tmpdir(), `node-dns-networks-${process.pid}-${Date.now()}.notthere`);
    const file = NetworksFile.fromFile(missing);
    assert.equal(file.entries.length, 0);
    assert.equal(file.sourcePath, missing);
});
test('NetworksFile.fromFile: parses content on real path', () => {
    const tmp = path.join(os.tmpdir(), `node-dns-networks-${process.pid}-${Date.now()}.txt`);
    fs.writeFileSync(tmp, 'loopback 127\nmynet 192.168.1 lan\n');
    try {
        const file = NetworksFile.fromFile(tmp);
        assert.equal(file.entries.length, 2);
        assert.equal(file.lookupByName('lan').name, 'mynet');
        assert.equal(file.sourcePath, tmp);
    }
    finally {
        fs.unlinkSync(tmp);
    }
});
test('NetworksFile#merge: earlier entries win on name + address collisions', () => {
    const base = NetworksFile.parse('mynet 10.0.0.0\nshared 192.168.1.0');
    const overlay = NetworksFile.parse('shared 192.168.2.0\nextra 172.16.0.0');
    const merged = base.merge(overlay);
    assert.equal(merged.lookupByName('shared').address, '192.168.1.0', 'base wins');
    assert.equal(merged.lookupByName('extra').address, '172.16.0.0', 'non-conflicting overlay added');
    assert.equal(merged.entries.length, 3);
});
test('NetworksFile.DEFAULT_PATH is /etc/networks', () => {
    assert.equal(NetworksFile.DEFAULT_PATH, '/etc/networks');
});
//# sourceMappingURL=networksFile.js.map