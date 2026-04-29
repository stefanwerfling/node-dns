import assert from 'assert';
import { Buffer } from 'buffer';
import * as crypto from 'crypto';
import { Dnssec, DnssecAlgorithm, DnssecDigest } from '../Lib/Dnssec.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { DS } from '../Packet/Types/DS.js';
import { NS } from '../Packet/Types/NS.js';
import { RRSIG } from '../Packet/Types/RRSIG.js';
import { DnssecChain } from '../Resolver/DnssecChain.js';
import { test } from './test.js';
const NOW = 1748736000;
const INCEPTION = '20240101000000';
const EXPIRATION = '20300101000000';
const ed25519Key = (flags) => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const dnskey = Dnssec.publicKeyToDnskey(publicKey, DnssecAlgorithm.ED25519, flags);
    return { privateKey: privateKey, dnskey: dnskey, keyTag: Dnssec.computeKeyTag(dnskey) };
};
const dsRecord = (key, owner) => {
    const digest = Dnssec.computeDsDigest(owner, key.dnskey, DnssecDigest.SHA256);
    return new DS(key.keyTag, key.dnskey.algorithm, DnssecDigest.SHA256, digest);
};
const dnskeyRecord = (owner, key, ttl = 3600) => new PacketResource(owner, key.dnskey, PacketClass.IN, ttl);
const rrsigRecord = (owner, sig, ttl = 3600) => new PacketResource(owner, sig, PacketClass.IN, ttl);
test('DnssecChain#validateDnskeyRrset secure when KSK matches DS and signs DNSKEY', () => {
    const zone = 'example.com';
    const ksk = ed25519Key(257);
    const dnskeys = [dnskeyRecord(zone, ksk)];
    const ds = dsRecord(ksk, zone);
    const sig = Dnssec.signRrset(zone, dnskeys, ksk.dnskey, ksk.privateKey, {
        inception: INCEPTION,
        expiration: EXPIRATION
    });
    const result = DnssecChain.validateDnskeyRrset(zone, dnskeys, [rrsigRecord(zone, sig)], [ds], { now: NOW });
    assert.equal(result.validity, 'secure');
    assert.equal(result.byKey?.keyTag, ksk.keyTag);
});
test('DnssecChain#validateDnskeyRrset bogus when DNSKEY set is empty', () => {
    const ds = new DS(1, 8, 2, 'aabbcc');
    const result = DnssecChain.validateDnskeyRrset('example.com', [], [], [ds], { now: NOW });
    assert.equal(result.validity, 'bogus');
});
test('DnssecChain#validateDnskeyRrset bogus when no RRSIG covers DNSKEY', () => {
    const zone = 'example.com';
    const ksk = ed25519Key(257);
    const ds = dsRecord(ksk, zone);
    const result = DnssecChain.validateDnskeyRrset(zone, [dnskeyRecord(zone, ksk)], [], [ds], { now: NOW });
    assert.equal(result.validity, 'bogus');
});
test('DnssecChain#validateDnskeyRrset bogus when no DNSKEY matches the parent DS', () => {
    const zone = 'example.com';
    const ksk = ed25519Key(257);
    const dnskeys = [dnskeyRecord(zone, ksk)];
    const sig = Dnssec.signRrset(zone, dnskeys, ksk.dnskey, ksk.privateKey, {
        inception: INCEPTION,
        expiration: EXPIRATION
    });
    const wrongDs = new DS(999, 8, 2, 'aabbccddeeff00112233445566778899');
    const result = DnssecChain.validateDnskeyRrset(zone, dnskeys, [rrsigRecord(zone, sig)], [wrongDs], { now: NOW });
    assert.equal(result.validity, 'bogus');
    assert.match(result.reason ?? '', /no DNSKEY matches/u);
});
test('DnssecChain#validateDnskeyRrset bogus when SEP flag is missing', () => {
    const zone = 'example.com';
    const zskOnly = ed25519Key(256);
    const dnskeys = [dnskeyRecord(zone, zskOnly)];
    const ds = dsRecord(zskOnly, zone);
    const sig = Dnssec.signRrset(zone, dnskeys, zskOnly.dnskey, zskOnly.privateKey, {
        inception: INCEPTION,
        expiration: EXPIRATION
    });
    const result = DnssecChain.validateDnskeyRrset(zone, dnskeys, [rrsigRecord(zone, sig)], [ds], { now: NOW });
    assert.equal(result.validity, 'bogus');
});
test('DnssecChain#validateDnskeyRrset secure when KSK + ZSK both present (KSK signs)', () => {
    const zone = 'example.com';
    const ksk = ed25519Key(257);
    const zsk = ed25519Key(256);
    const dnskeys = [dnskeyRecord(zone, ksk), dnskeyRecord(zone, zsk)];
    const sig = Dnssec.signRrset(zone, dnskeys, ksk.dnskey, ksk.privateKey, {
        inception: INCEPTION,
        expiration: EXPIRATION
    });
    const ds = dsRecord(ksk, zone);
    const result = DnssecChain.validateDnskeyRrset(zone, dnskeys, [rrsigRecord(zone, sig)], [ds], { now: NOW });
    assert.equal(result.validity, 'secure');
    assert.equal(result.byKey?.keyTag, ksk.keyTag);
});
test('DnssecChain#validateRrset secure when ZSK signs the RRset', () => {
    const zone = 'example.com';
    const zsk = ed25519Key(256);
    const rrset = [
        new PacketResource('www.example.com', new A('192.0.2.1'), PacketClass.IN, 300)
    ];
    const sig = Dnssec.signRrset('www.example.com', rrset, zsk.dnskey, zsk.privateKey, {
        inception: INCEPTION,
        expiration: EXPIRATION,
        signer: zone
    });
    const result = DnssecChain.validateRrset('www.example.com', rrset, [rrsigRecord('www.example.com', sig)], [dnskeyRecord(zone, zsk)], { now: NOW });
    assert.equal(result.validity, 'secure');
});
test('DnssecChain#validateRrset insecure when no RRSIG covers the RRset', () => {
    const result = DnssecChain.validateRrset('www.example.com', [new PacketResource('www.example.com', new A('192.0.2.1'), PacketClass.IN, 300)], [], [], { now: NOW });
    assert.equal(result.validity, 'insecure');
});
test('DnssecChain#validateRrset bogus when no DNSKEY has the ZONE flag', () => {
    const zone = 'example.com';
    const sepOnly = ed25519Key(1);
    const rrset = [
        new PacketResource('www.example.com', new A('192.0.2.1'), PacketClass.IN, 300)
    ];
    const sig = Dnssec.signRrset('www.example.com', rrset, sepOnly.dnskey, sepOnly.privateKey, {
        inception: INCEPTION,
        expiration: EXPIRATION,
        signer: zone
    });
    const result = DnssecChain.validateRrset('www.example.com', rrset, [rrsigRecord('www.example.com', sig)], [dnskeyRecord(zone, sepOnly)], { now: NOW });
    assert.equal(result.validity, 'bogus');
});
test('DnssecChain#validateRrset bogus when RRSIG keyTag matches no DNSKEY', () => {
    const zone = 'example.com';
    const zsk = ed25519Key(256);
    const otherZsk = ed25519Key(256);
    const rrset = [
        new PacketResource('www.example.com', new A('192.0.2.1'), PacketClass.IN, 300)
    ];
    const sig = Dnssec.signRrset('www.example.com', rrset, zsk.dnskey, zsk.privateKey, {
        inception: INCEPTION,
        expiration: EXPIRATION,
        signer: zone
    });
    const result = DnssecChain.validateRrset('www.example.com', rrset, [rrsigRecord('www.example.com', sig)], [dnskeyRecord(zone, otherZsk)], { now: NOW });
    assert.equal(result.validity, 'bogus');
});
test('DnssecChain#validateRrset bogus when RRSIG signature is forged', () => {
    const zone = 'example.com';
    const zsk = ed25519Key(256);
    const rrset = [
        new PacketResource('www.example.com', new A('192.0.2.1'), PacketClass.IN, 300)
    ];
    const sig = Dnssec.signRrset('www.example.com', rrset, zsk.dnskey, zsk.privateKey, {
        inception: INCEPTION,
        expiration: EXPIRATION,
        signer: zone
    });
    const tampered = new RRSIG(sig.sigType, sig.algorithm, sig.labels, sig.originalTtl, sig.expiration, sig.inception, sig.keyTag, sig.signer, Buffer.alloc(64).toString('base64'));
    const result = DnssecChain.validateRrset('www.example.com', rrset, [rrsigRecord('www.example.com', tampered)], [dnskeyRecord(zone, zsk)], { now: NOW });
    assert.equal(result.validity, 'bogus');
});
test('DnssecChain#rrsigsFor filters by owner and covered type', () => {
    const sigA = new RRSIG(PacketTypes.A, 15, 2, 300, EXPIRATION, INCEPTION, 1, 'example.com', '');
    const sigMx = new RRSIG(PacketTypes.MX, 15, 2, 300, EXPIRATION, INCEPTION, 1, 'example.com', '');
    const records = [
        new PacketResource('www.example.com', sigA, PacketClass.IN, 300),
        new PacketResource('www.example.com', sigMx, PacketClass.IN, 300),
        new PacketResource('mail.example.com', sigA, PacketClass.IN, 300)
    ];
    const matching = DnssecChain.rrsigsFor(records, 'www.example.com', PacketTypes.A);
    assert.equal(matching.length, 1);
    assert.equal(matching[0].packetType.sigType, PacketTypes.A);
});
test('DnssecChain#groupRrsets buckets by (name, type, class), strips RRSIG/OPT', () => {
    const records = [
        new PacketResource('a.example.com', new A('1.1.1.1'), PacketClass.IN, 300),
        new PacketResource('a.example.com', new A('2.2.2.2'), PacketClass.IN, 300),
        new PacketResource('b.example.com', new A('3.3.3.3'), PacketClass.IN, 300),
        new PacketResource('a.example.com', new NS('ns.example.com'), PacketClass.IN, 300),
        new PacketResource('a.example.com', new RRSIG(PacketTypes.A, 15, 2, 300, EXPIRATION, INCEPTION, 0, 'example.com', ''), PacketClass.IN, 300)
    ];
    const groups = DnssecChain.groupRrsets(records);
    assert.equal(groups.size, 3);
    assert.equal(groups.get('a.example.com|1|1').length, 2);
    assert.equal(groups.get('b.example.com|1|1').length, 1);
    assert.equal(groups.get('a.example.com|2|1').length, 1);
});
test('DnssecChain#dnskeysAt picks DNSKEYs at the named zone', () => {
    const zone = 'example.com';
    const zsk = ed25519Key(256);
    const records = [
        dnskeyRecord(zone, zsk),
        dnskeyRecord('other.example', zsk),
        new PacketResource(zone, new A('1.1.1.1'), PacketClass.IN, 300)
    ];
    const found = DnssecChain.dnskeysAt(records, zone);
    assert.equal(found.length, 1);
    assert.equal(found[0].name, zone);
});
//# sourceMappingURL=dnssecChain.js.map