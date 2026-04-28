import assert from 'assert';
import { Buffer } from 'buffer';
import * as crypto from 'crypto';
import { Dnssec, DnssecAlgorithm, DnssecDigest } from '../Lib/Dnssec.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { AAAA } from '../Packet/Types/AAAA.js';
import { DNSKEY } from '../Packet/Types/DNSKEY.js';
import { DS } from '../Packet/Types/DS.js';
import { MX } from '../Packet/Types/MX.js';
import { NAPTR } from '../Packet/Types/NAPTR.js';
import { NS } from '../Packet/Types/NS.js';
import { NSEC } from '../Packet/Types/NSEC.js';
import { RRSIG } from '../Packet/Types/RRSIG.js';
import { SOA } from '../Packet/Types/SOA.js';
import { SRV } from '../Packet/Types/SRV.js';
import { test } from './test.js';
const OWNER = 'example.com';
const SIGNER = 'example.com';
const ORIGINAL_TTL = 3600;
const INCEPTION = '20240101000000';
const EXPIRATION = '20300101000000';
const NOW = 1748736000;
const buildA = (address) => {
    return new PacketResource(OWNER, new A(address), PacketClass.IN, ORIGINAL_TTL);
};
const buildRrsig = (algorithm, sigType = PacketTypes.A) => {
    return new RRSIG(sigType, algorithm, OWNER.split('.').length, ORIGINAL_TTL, EXPIRATION, INCEPTION, 0, SIGNER, '');
};
const rsaDnskey = (pubKey, algorithm) => {
    const jwk = pubKey.export({ format: 'jwk' });
    const exponent = Buffer.from(jwk.e, 'base64url');
    const modulus = Buffer.from(jwk.n, 'base64url');
    let prefix;
    if (exponent.length <= 255) {
        prefix = Buffer.from([exponent.length]);
    }
    else {
        const buf = Buffer.alloc(3);
        buf.writeUInt8(0, 0);
        buf.writeUInt16BE(exponent.length, 1);
        prefix = buf;
    }
    const rdata = Buffer.concat([prefix, exponent, modulus]);
    return new DNSKEY(257, 3, algorithm, rdata.toString('base64'));
};
const ecdsaDnskey = (pubKey, algorithm, curveBytes) => {
    const jwk = pubKey.export({ format: 'jwk' });
    const x = Buffer.from(jwk.x, 'base64url');
    const y = Buffer.from(jwk.y, 'base64url');
    const padX = Buffer.concat([Buffer.alloc(curveBytes - x.length), x]);
    const padY = Buffer.concat([Buffer.alloc(curveBytes - y.length), y]);
    const rdata = Buffer.concat([padX, padY]);
    return new DNSKEY(257, 3, algorithm, rdata.toString('base64'));
};
const ed25519Dnskey = (pubKey) => {
    const jwk = pubKey.export({ format: 'jwk' });
    const rdata = Buffer.from(jwk.x, 'base64url');
    return new DNSKEY(257, 3, DnssecAlgorithm.ED25519, rdata.toString('base64'));
};
test('Dnssec#verify RSA/SHA-256 (algo 8)', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const dnskey = rsaDnskey(publicKey, DnssecAlgorithm.RSASHA256);
    const rrsig = buildRrsig(DnssecAlgorithm.RSASHA256);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);
    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign('sha256', input, privateKey).toString('base64');
    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, { now: NOW }));
});
test('Dnssec#verify RSA/SHA-512 (algo 10)', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const dnskey = rsaDnskey(publicKey, DnssecAlgorithm.RSASHA512);
    const rrsig = buildRrsig(DnssecAlgorithm.RSASHA512);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);
    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign('sha512', input, privateKey).toString('base64');
    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, { now: NOW }));
});
test('Dnssec#verify ECDSA P-256 / SHA-256 (algo 13)', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const dnskey = ecdsaDnskey(publicKey, DnssecAlgorithm.ECDSAP256SHA256, 32);
    const rrsig = buildRrsig(DnssecAlgorithm.ECDSAP256SHA256);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);
    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign('sha256', input, { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, { now: NOW }));
});
test('Dnssec#verify ECDSA P-384 / SHA-384 (algo 14)', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const dnskey = ecdsaDnskey(publicKey, DnssecAlgorithm.ECDSAP384SHA384, 48);
    const rrsig = buildRrsig(DnssecAlgorithm.ECDSAP384SHA384);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);
    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign('sha384', input, { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, { now: NOW }));
});
test('Dnssec#verify Ed25519 (algo 15)', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);
    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');
    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, { now: NOW }));
});
test('Dnssec#verify multi-record RRset (canonical RDATA sort)', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);
    const rrset = [buildA('192.0.2.7'), buildA('192.0.2.1'), buildA('192.0.2.3')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');
    const shuffled = [rrset[2], rrset[0], rrset[1]];
    assert.ok(Dnssec.verifyRrsig(OWNER, shuffled, rrsig, dnskey, { now: NOW }));
});
test('Dnssec#verify AAAA RRset', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519, PacketTypes.AAAA);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);
    const rrset = [
        new PacketResource(OWNER, new AAAA('2001:db8::1'), PacketClass.IN, ORIGINAL_TTL)
    ];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');
    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, { now: NOW }));
});
test('Dnssec#verify NS RRset (lowercased embedded name in canonical RDATA)', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519, PacketTypes.NS);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);
    const rrset = [
        new PacketResource(OWNER, new NS('NS1.Example.com'), PacketClass.IN, ORIGINAL_TTL),
        new PacketResource(OWNER, new NS('ns2.example.com'), PacketClass.IN, ORIGINAL_TTL),
    ];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');
    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, { now: NOW }));
});
test('Dnssec#verify rejects mismatched key tag', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519);
    rrsig.keyTag = (Dnssec.computeKeyTag(dnskey) ^ 0xFFFF) & 0xFFFF;
    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');
    assert.equal(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, { now: NOW }), false);
});
test('Dnssec#verify rejects tampered signature', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);
    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    const sig = crypto.sign(null, input, privateKey);
    sig[0] ^= 0x01;
    rrsig.signature = sig.toString('base64');
    assert.equal(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, { now: NOW }), false);
});
test('Dnssec#verify rejects RRset mutated after signing', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);
    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');
    const tampered = [buildA('192.0.2.99')];
    assert.equal(Dnssec.verifyRrsig(OWNER, tampered, rrsig, dnskey, { now: NOW }), false);
});
test('Dnssec#verify rejects signature outside validity window', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);
    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');
    const longAfter = 7258118400;
    assert.equal(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, { now: longAfter }), false);
});
test('Dnssec#verify accepts expired signature when skipValidityWindow', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);
    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');
    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, { skipValidityWindow: true }));
});
test('Dnssec#verifyDs round-trip (SHA-256 digest)', () => {
    const { publicKey } = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const owner = 'sub.example.com';
    const ds = new DS(Dnssec.computeKeyTag(dnskey), DnssecAlgorithm.ED25519, DnssecDigest.SHA256, Dnssec.computeDsDigest(owner, dnskey, DnssecDigest.SHA256));
    assert.ok(Dnssec.verifyDs(owner, dnskey, ds));
});
test('Dnssec#verifyDs rejects mismatched digest', () => {
    const { publicKey } = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const ds = new DS(Dnssec.computeKeyTag(dnskey), DnssecAlgorithm.ED25519, DnssecDigest.SHA256, '00'.repeat(32));
    assert.equal(Dnssec.verifyDs('example.com', dnskey, ds), false);
});
test('Dnssec#computeKeyTag matches RFC 4034 Appendix B reference', () => {
    const dnskey = new DNSKEY(257, 3, 8, 'AAEC');
    assert.equal(Dnssec.computeKeyTag(dnskey), 0x060A);
});
const signAndVerify = (type, record, owner = OWNER) => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519, type);
    rrsig.signer = SIGNER;
    rrsig.labels = owner.split('.').filter((l) => l.length > 0).length;
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);
    const rrset = [record];
    const input = Dnssec.buildSigningInput(owner, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');
    return Dnssec.verifyRrsig(owner, rrset, rrsig, dnskey, { now: NOW });
};
test('Dnssec#canonical RDATA: SOA round-trips', () => {
    const soa = new SOA('NS1.Example.com', 'ADMIN.Example.com', 2025010101, 7200, 3600, 1209600, 3600);
    const rr = new PacketResource(OWNER, soa, PacketClass.IN, ORIGINAL_TTL);
    assert.ok(signAndVerify(PacketTypes.SOA, rr));
});
test('Dnssec#canonical RDATA: SRV round-trips with mixed-case target', () => {
    const srv = new SRV(10, 20, 5060, 'Sip.Example.com');
    const rr = new PacketResource('_sip._tcp.example.com', srv, PacketClass.IN, ORIGINAL_TTL);
    assert.ok(signAndVerify(PacketTypes.SRV, rr, '_sip._tcp.example.com'));
});
test('Dnssec#canonical RDATA: NAPTR round-trips (replacement lowercased, char-strings preserved)', () => {
    const naptr = new NAPTR(100, 50, 'U', 'E2U+sip', '!^.*$!sip:info@example.com!', '_Sip._Tcp.Example.com');
    const rr = new PacketResource(OWNER, naptr, PacketClass.IN, ORIGINAL_TTL);
    assert.ok(signAndVerify(PacketTypes.NAPTR, rr));
});
test('Dnssec#canonical RDATA: NSEC round-trips with lowercased nextDomain', () => {
    const nsec = new NSEC('AlphA.Example.com', [PacketTypes.A, PacketTypes.AAAA, PacketTypes.RRSIG, PacketTypes.NSEC]);
    const rr = new PacketResource(OWNER, nsec, PacketClass.IN, ORIGINAL_TTL);
    assert.ok(signAndVerify(PacketTypes.NSEC, rr));
});
test('Dnssec#canonical RDATA: RRSIG-of-RRSIG round-trips with lowercased signer', () => {
    const inner = new RRSIG(PacketTypes.A, DnssecAlgorithm.ED25519, 2, 3600, EXPIRATION, INCEPTION, 12345, 'Inner.Example.com', 'AA==');
    const rr = new PacketResource(OWNER, inner, PacketClass.IN, ORIGINAL_TTL);
    assert.ok(signAndVerify(PacketTypes.RRSIG, rr));
});
test('Dnssec#wildcard expansion: signed *.example.com verifies under host.example.com', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = new RRSIG(PacketTypes.A, DnssecAlgorithm.ED25519, 2, ORIGINAL_TTL, EXPIRATION, INCEPTION, Dnssec.computeKeyTag(dnskey), SIGNER, '');
    const expandedOwner = 'host.example.com';
    const rrset = [
        new PacketResource(expandedOwner, new A('192.0.2.1'), PacketClass.IN, ORIGINAL_TTL)
    ];
    const input = Dnssec.buildSigningInput(expandedOwner, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');
    assert.ok(Dnssec.verifyRrsig(expandedOwner, rrset, rrsig, dnskey, { now: NOW }));
});
test('Dnssec#wildcard expansion: deep query under same wildcard verifies', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = new RRSIG(PacketTypes.A, DnssecAlgorithm.ED25519, 2, ORIGINAL_TTL, EXPIRATION, INCEPTION, Dnssec.computeKeyTag(dnskey), SIGNER, '');
    const expanded = 'a.b.c.example.com';
    const rrset = [new PacketResource(expanded, new A('192.0.2.1'), PacketClass.IN, ORIGINAL_TTL)];
    rrsig.signature = crypto.sign(null, Dnssec.buildSigningInput(expanded, rrset, rrsig), privateKey).toString('base64');
    assert.ok(Dnssec.verifyRrsig(expanded, rrset, rrsig, dnskey, { now: NOW }));
});
test('Dnssec#wildcard expansion: labels > owner labels is rejected', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = new RRSIG(PacketTypes.A, DnssecAlgorithm.ED25519, 5, ORIGINAL_TTL, EXPIRATION, INCEPTION, Dnssec.computeKeyTag(dnskey), SIGNER, '');
    const rrset = [new PacketResource(OWNER, new A('192.0.2.1'), PacketClass.IN, ORIGINAL_TTL)];
    rrsig.signature = crypto.sign(null, Buffer.from('whatever'), privateKey).toString('base64');
    assert.equal(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, { now: NOW }), false);
});
test('Dnssec#verify MX RRset (existing single-name canonical) regression', () => {
    const mx1 = new PacketResource(OWNER, new MX('Mail1.Example.com', 10), PacketClass.IN, ORIGINAL_TTL);
    const mx2 = new PacketResource(OWNER, new MX('mail2.example.com', 20), PacketClass.IN, ORIGINAL_TTL);
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519, PacketTypes.MX);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);
    const rrset = [mx1, mx2];
    rrsig.signature = crypto.sign(null, Dnssec.buildSigningInput(OWNER, rrset, rrsig), privateKey).toString('base64');
    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, { now: NOW }));
});
test('Dnssec#verifyRrsig throws on unsupported algorithm', () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    dnskey.algorithm = 5;
    const rrsig = buildRrsig(5);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);
    const rrset = [buildA('192.0.2.1')];
    rrsig.signature = crypto.sign(null, Buffer.from('x'), privateKey).toString('base64');
    assert.throws(() => Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, { now: NOW }));
});
//# sourceMappingURL=dnssec.js.map