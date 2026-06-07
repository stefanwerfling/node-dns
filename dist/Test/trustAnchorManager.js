import assert from 'assert';
import { Buffer } from 'buffer';
import crypto from 'crypto';
import { Dnssec, DnssecAlgorithm } from '../Lib/Dnssec.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { DNSKEY } from '../Packet/Types/DNSKEY.js';
import { DS } from '../Packet/Types/DS.js';
import { TrustAnchors } from '../Resolver/TrustAnchor.js';
import { TrustAnchorManager } from '../Resolver/TrustAnchorManager.js';
import { test } from './test.js';
const ZONE = '.';
const OWNER = '.';
const buildEd25519Dnskey = (flags = 257) => {
    const { publicKey } = crypto.generateKeyPairSync('ed25519');
    const jwk = publicKey.export({ format: 'jwk' });
    const rdata = Buffer.from(jwk.x, 'base64url');
    const dnskey = new DNSKEY(flags, 3, DnssecAlgorithm.ED25519, rdata.toString('base64'));
    dnskey.keyTag = Dnssec.computeKeyTag(dnskey);
    const record = new PacketResource(OWNER, dnskey, PacketClass.IN, 3600);
    return { dnskey: dnskey, record: record };
};
const buildAnchorFor = (dnskey) => {
    const digestHex = Dnssec.computeDsDigest(OWNER, dnskey, 2);
    return {
        zone: ZONE,
        ds: new DS(dnskey.keyTag, dnskey.algorithm, 2, digestHex)
    };
};
test('TrustAnchorManager: matching initialAnchor seeds key directly as Valid', () => {
    const { dnskey, record } = buildEd25519Dnskey();
    const anchor = buildAnchorFor(dnskey);
    const manager = new TrustAnchorManager({ initialAnchors: [anchor] });
    const events = manager.update(ZONE, [record]);
    const keys = manager.getKeys(ZONE);
    assert.equal(keys.length, 1);
    assert.equal(keys[0].state, 'Valid');
    assert.equal(keys[0].keyTag, dnskey.keyTag);
    assert.ok(events.some((e) => e.type === 'added' && e.keyTag === dnskey.keyTag));
});
test('TrustAnchorManager: new key without matching DS lands as AddPending', () => {
    const { record: anchored } = buildEd25519Dnskey();
    const anchor = buildAnchorFor(anchored.packetType);
    const { dnskey: newKey, record: newRecord } = buildEd25519Dnskey();
    const manager = new TrustAnchorManager({ initialAnchors: [anchor] });
    manager.update(ZONE, [anchored, newRecord]);
    const keys = manager.getKeys(ZONE);
    const fresh = keys.find((k) => k.keyTag === newKey.keyTag);
    assert.ok(fresh !== undefined);
    assert.equal(fresh.state, 'AddPending');
});
test('TrustAnchorManager: AddPending → Valid after add-hold-down window', () => {
    let clock = 1_000_000;
    const { record: anchored } = buildEd25519Dnskey();
    const anchor = buildAnchorFor(anchored.packetType);
    const { dnskey: newKey, record: newRecord } = buildEd25519Dnskey();
    const manager = new TrustAnchorManager({
        initialAnchors: [anchor],
        addHoldDownMs: 1000,
        now: () => clock
    });
    manager.update(ZONE, [anchored, newRecord]);
    assert.equal(manager.getKeys(ZONE).find((k) => k.keyTag === newKey.keyTag).state, 'AddPending');
    clock += 1500;
    const events = manager.update(ZONE, [anchored, newRecord]);
    assert.equal(manager.getKeys(ZONE).find((k) => k.keyTag === newKey.keyTag).state, 'Valid');
    assert.ok(events.some((e) => e.type === 'promoted' && e.keyTag === newKey.keyTag));
});
test('TrustAnchorManager: AddPending key disappears before hold-down ends → Removed (continuous-visibility rule)', () => {
    let clock = 1_000_000;
    const { record: anchored } = buildEd25519Dnskey();
    const anchor = buildAnchorFor(anchored.packetType);
    const { dnskey: newKey, record: newRecord } = buildEd25519Dnskey();
    const manager = new TrustAnchorManager({
        initialAnchors: [anchor],
        addHoldDownMs: 1000,
        now: () => clock
    });
    manager.update(ZONE, [anchored, newRecord]);
    clock += 500;
    manager.update(ZONE, [anchored]);
    const keys = manager.getKeys(ZONE);
    assert.equal(keys.find((k) => k.keyTag === newKey.keyTag), undefined, 'AddPending dropped on first miss');
});
test('TrustAnchorManager: Valid → Missing on disappearance, Missing → Removed after remove-hold-down', () => {
    let clock = 1_000_000;
    const { dnskey: k1, record: r1 } = buildEd25519Dnskey();
    const anchor = buildAnchorFor(k1);
    const manager = new TrustAnchorManager({
        initialAnchors: [anchor],
        removeHoldDownMs: 1000,
        now: () => clock
    });
    manager.update(ZONE, [r1]);
    assert.equal(manager.getKeys(ZONE)[0].state, 'Valid');
    clock += 100;
    const events1 = manager.update(ZONE, []);
    assert.equal(manager.getKeys(ZONE)[0].state, 'Missing');
    assert.ok(events1.some((e) => e.type === 'missing' && e.keyTag === k1.keyTag));
    clock += 100;
    manager.update(ZONE, []);
    assert.equal(manager.getKeys(ZONE)[0].state, 'Missing');
    clock += 5000;
    const events2 = manager.update(ZONE, []);
    assert.equal(manager.getKeys(ZONE).length, 0, 'Removed entries are GC\'d');
    assert.ok(events2.some((e) => e.type === 'removed' && e.keyTag === k1.keyTag));
});
test('TrustAnchorManager: Missing → Valid when key reappears', () => {
    let clock = 1_000_000;
    const { dnskey, record } = buildEd25519Dnskey();
    const anchor = buildAnchorFor(dnskey);
    const manager = new TrustAnchorManager({
        initialAnchors: [anchor],
        now: () => clock
    });
    manager.update(ZONE, [record]);
    clock += 100;
    manager.update(ZONE, []);
    assert.equal(manager.getKeys(ZONE)[0].state, 'Missing');
    clock += 100;
    const events = manager.update(ZONE, [record]);
    assert.equal(manager.getKeys(ZONE)[0].state, 'Valid');
    assert.ok(events.some((e) => e.type === 'restored' && e.keyTag === dnskey.keyTag));
});
test('TrustAnchorManager: REVOKE bit on a Valid key transitions to Revoked immediately', () => {
    let clock = 1_000_000;
    const { dnskey, record } = buildEd25519Dnskey();
    const anchor = buildAnchorFor(dnskey);
    const manager = new TrustAnchorManager({
        initialAnchors: [anchor],
        now: () => clock
    });
    manager.update(ZONE, [record]);
    assert.equal(manager.getKeys(ZONE)[0].state, 'Valid');
    const revokedDnskey = new DNSKEY(257 | 0x0080, 3, dnskey.algorithm, dnskey.key);
    revokedDnskey.keyTag = dnskey.keyTag;
    const revokedRecord = new PacketResource(OWNER, revokedDnskey, PacketClass.IN, 3600);
    clock += 100;
    const events = manager.update(ZONE, [revokedRecord]);
    assert.equal(manager.getKeys(ZONE)[0].state, 'Revoked');
    assert.ok(events.some((e) => e.type === 'revoked' && e.keyTag === dnskey.keyTag));
});
test('TrustAnchorManager: REVOKE on never-trusted key is ignored (no spurious anchor)', () => {
    const { record: anchored } = buildEd25519Dnskey();
    const anchor = buildAnchorFor(anchored.packetType);
    const { publicKey } = crypto.generateKeyPairSync('ed25519');
    const jwk = publicKey.export({ format: 'jwk' });
    const rdata = Buffer.from(jwk.x, 'base64url');
    const evilDnskey = new DNSKEY(257 | 0x0080, 3, DnssecAlgorithm.ED25519, rdata.toString('base64'));
    evilDnskey.keyTag = Dnssec.computeKeyTag(evilDnskey);
    const evilRecord = new PacketResource(OWNER, evilDnskey, PacketClass.IN, 3600);
    const manager = new TrustAnchorManager({ initialAnchors: [anchor] });
    manager.update(ZONE, [anchored, evilRecord]);
    const evilEntry = manager.getKeys(ZONE).find((k) => k.keyTag === evilDnskey.keyTag);
    assert.equal(evilEntry, undefined, 'never-trusted REVOKE key not added');
});
test('TrustAnchorManager: currentAnchors returns initial anchors before first observation', () => {
    const { dnskey, record } = buildEd25519Dnskey();
    const anchor = buildAnchorFor(dnskey);
    const manager = new TrustAnchorManager({ initialAnchors: [anchor] });
    const before = manager.currentAnchors(ZONE);
    assert.equal(before.length, 1);
    assert.equal(before[0].ds.keyTag, dnskey.keyTag);
    manager.update(ZONE, [record]);
    const after = manager.currentAnchors(ZONE);
    assert.equal(after.length, 1);
    assert.equal(after[0].ds.keyTag, dnskey.keyTag);
});
test('TrustAnchorManager: serialize / fromSerialized round-trip preserves state and timers', () => {
    let clock = 1_000_000;
    const { dnskey, record } = buildEd25519Dnskey();
    const anchor = buildAnchorFor(dnskey);
    const manager1 = new TrustAnchorManager({
        initialAnchors: [anchor],
        addHoldDownMs: 1000,
        now: () => clock
    });
    manager1.update(ZONE, [record]);
    const dumped = manager1.serialize();
    const manager2 = TrustAnchorManager.fromSerialized(dumped, {
        initialAnchors: [anchor],
        addHoldDownMs: 1000,
        now: () => clock
    });
    const keys = manager2.getKeys(ZONE);
    assert.equal(keys.length, 1);
    assert.equal(keys[0].state, 'Valid');
    assert.equal(keys[0].keyTag, dnskey.keyTag);
});
test('TrustAnchorManager: forgetZone clears state and re-enables seeding', () => {
    const { record } = buildEd25519Dnskey();
    const anchor = buildAnchorFor(record.packetType);
    const manager = new TrustAnchorManager({ initialAnchors: [anchor] });
    manager.update(ZONE, [record]);
    assert.equal(manager.getKeys(ZONE).length, 1);
    manager.forgetZone(ZONE);
    assert.equal(manager.getKeys(ZONE).length, 0);
    manager.update(ZONE, [record]);
    assert.equal(manager.getKeys(ZONE)[0].state, 'Valid');
});
test('TrustAnchorManager: events fire via EventEmitter', () => {
    const { dnskey, record } = buildEd25519Dnskey();
    const anchor = buildAnchorFor(dnskey);
    const manager = new TrustAnchorManager({ initialAnchors: [anchor] });
    const added = [];
    manager.on('added', (e) => added.push(e.keyTag));
    manager.update(ZONE, [record]);
    assert.deepEqual(added, [dnskey.keyTag]);
});
test('TrustAnchorManager: rollover overlap — old + new key both Valid', () => {
    let clock = 1_000_000;
    const { dnskey: ksk1, record: r1 } = buildEd25519Dnskey();
    const anchor = buildAnchorFor(ksk1);
    const { dnskey: ksk2, record: r2 } = buildEd25519Dnskey();
    const manager = new TrustAnchorManager({
        initialAnchors: [anchor],
        addHoldDownMs: 1000,
        now: () => clock
    });
    manager.update(ZONE, [r1]);
    clock += 100;
    manager.update(ZONE, [r1, r2]);
    clock += 1500;
    manager.update(ZONE, [r1, r2]);
    const valid = manager.getKeys(ZONE).filter((k) => k.state === 'Valid');
    assert.equal(valid.length, 2, 'both KSKs Valid during rollover overlap');
    const anchors = manager.currentAnchors(ZONE);
    assert.equal(anchors.length, 2);
    assert.ok(anchors.some((a) => a.ds.keyTag === ksk1.keyTag));
    assert.ok(anchors.some((a) => a.ds.keyTag === ksk2.keyTag));
});
test('TrustAnchorManager: non-SEP keys are ignored (only KSKs participate)', () => {
    const zsk = buildEd25519Dnskey(256);
    const manager = new TrustAnchorManager();
    manager.update(ZONE, [zsk.record]);
    assert.equal(manager.getKeys(ZONE).length, 0);
});
test('TrustAnchors.findAllFor returns all anchors tied at the deepest zone', () => {
    const a1 = buildEd25519Dnskey();
    const a2 = buildEd25519Dnskey();
    const anchor1 = buildAnchorFor(a1.dnskey);
    const anchor2 = buildAnchorFor(a2.dnskey);
    const found = TrustAnchors.findAllFor([anchor1, anchor2], 'example.com');
    assert.equal(found.length, 2);
});
//# sourceMappingURL=trustAnchorManager.js.map