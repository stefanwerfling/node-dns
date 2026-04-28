import assert from 'assert';
import { Buffer } from 'buffer';
import * as crypto from 'crypto';
import {Dnssec, DnssecAlgorithm, DnssecDigest} from '../Lib/Dnssec.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {AAAA} from '../Packet/Types/AAAA.js';
import {DNSKEY} from '../Packet/Types/DNSKEY.js';
import {DS} from '../Packet/Types/DS.js';
import {NS} from '../Packet/Types/NS.js';
import {RRSIG} from '../Packet/Types/RRSIG.js';
import {test} from './test.js';

const OWNER = 'example.com';
const SIGNER = 'example.com';
const ORIGINAL_TTL = 3600;
const INCEPTION = '20240101000000';
const EXPIRATION = '20300101000000';
// 2025-06-01T00:00:00Z — fixed inside the [INCEPTION, EXPIRATION] window so
// the validity-window check passes deterministically across CI clock drift.
const NOW = 1748736000;

const buildA = (address: string): PacketResource => {
    return new PacketResource(OWNER, new A(address), PacketClass.IN, ORIGINAL_TTL);
};

const buildRrsig = (algorithm: number, sigType: number = PacketTypes.A): RRSIG => {
    return new RRSIG(
        sigType,
        algorithm,
        OWNER.split('.').length,
        ORIGINAL_TTL,
        EXPIRATION,
        INCEPTION,
        0,        // keyTag — patched below once we know the DNSKEY
        SIGNER,
        ''        // signature — patched below
    );
};

/**
 * Build the RFC 3110 RSA DNSKEY RDATA `[explen | exp | mod]` (base64) from
 * a Node KeyObject.
 */
const rsaDnskey = (pubKey: crypto.KeyObject, algorithm: number): DNSKEY => {
    const jwk = pubKey.export({format: 'jwk'}) as {n: string; e: string;};
    const exponent = Buffer.from(jwk.e, 'base64url');
    const modulus = Buffer.from(jwk.n, 'base64url');

    let prefix: Buffer;

    if (exponent.length <= 255) {
        prefix = Buffer.from([exponent.length]);
    } else {
        const buf = Buffer.alloc(3);
        buf.writeUInt8(0, 0);
        buf.writeUInt16BE(exponent.length, 1);
        prefix = buf;
    }

    const rdata = Buffer.concat([prefix, exponent, modulus]);
    return new DNSKEY(257, 3, algorithm, rdata.toString('base64'));
};

const ecdsaDnskey = (pubKey: crypto.KeyObject, algorithm: number, curveBytes: number): DNSKEY => {
    const jwk = pubKey.export({format: 'jwk'}) as {x: string; y: string;};
    const x = Buffer.from(jwk.x, 'base64url');
    const y = Buffer.from(jwk.y, 'base64url');

    // JWK left-pads x/y to the curve coordinate size (RFC 7518 §6.2.1.2),
    // but defensively re-pad here in case Node ever returns minimum-length
    // representations.
    const padX = Buffer.concat([Buffer.alloc(curveBytes - x.length), x]);
    const padY = Buffer.concat([Buffer.alloc(curveBytes - y.length), y]);

    const rdata = Buffer.concat([padX, padY]);
    return new DNSKEY(257, 3, algorithm, rdata.toString('base64'));
};

const ed25519Dnskey = (pubKey: crypto.KeyObject): DNSKEY => {
    const jwk = pubKey.export({format: 'jwk'}) as {x: string;};
    const rdata = Buffer.from(jwk.x, 'base64url');
    return new DNSKEY(257, 3, DnssecAlgorithm.ED25519, rdata.toString('base64'));
};

test('Dnssec#verify RSA/SHA-256 (algo 8)', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});
    const dnskey = rsaDnskey(publicKey, DnssecAlgorithm.RSASHA256);
    const rrsig = buildRrsig(DnssecAlgorithm.RSASHA256);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);

    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign('sha256', input, privateKey).toString('base64');

    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {now: NOW}));
});

test('Dnssec#verify RSA/SHA-512 (algo 10)', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});
    const dnskey = rsaDnskey(publicKey, DnssecAlgorithm.RSASHA512);
    const rrsig = buildRrsig(DnssecAlgorithm.RSASHA512);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);

    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign('sha512', input, privateKey).toString('base64');

    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {now: NOW}));
});

test('Dnssec#verify ECDSA P-256 / SHA-256 (algo 13)', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ec', {namedCurve: 'P-256'});
    const dnskey = ecdsaDnskey(publicKey, DnssecAlgorithm.ECDSAP256SHA256, 32);
    const rrsig = buildRrsig(DnssecAlgorithm.ECDSAP256SHA256);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);

    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign(
        'sha256',
        input,
        {key: privateKey, dsaEncoding: 'ieee-p1363'}
    ).toString('base64');

    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {now: NOW}));
});

test('Dnssec#verify ECDSA P-384 / SHA-384 (algo 14)', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ec', {namedCurve: 'P-384'});
    const dnskey = ecdsaDnskey(publicKey, DnssecAlgorithm.ECDSAP384SHA384, 48);
    const rrsig = buildRrsig(DnssecAlgorithm.ECDSAP384SHA384);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);

    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign(
        'sha384',
        input,
        {key: privateKey, dsaEncoding: 'ieee-p1363'}
    ).toString('base64');

    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {now: NOW}));
});

test('Dnssec#verify Ed25519 (algo 15)', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);

    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');

    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {now: NOW}));
});

test('Dnssec#verify multi-record RRset (canonical RDATA sort)', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);

    // Order on the wire shouldn't matter — verifier always sorts by
    // canonical RDATA before hashing.
    const rrset = [buildA('192.0.2.7'), buildA('192.0.2.1'), buildA('192.0.2.3')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');

    const shuffled = [rrset[2], rrset[0], rrset[1]];
    assert.ok(Dnssec.verifyRrsig(OWNER, shuffled, rrsig, dnskey, {now: NOW}));
});

test('Dnssec#verify AAAA RRset', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519, PacketTypes.AAAA);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);

    const rrset = [
        new PacketResource(OWNER, new AAAA('2001:db8::1'), PacketClass.IN, ORIGINAL_TTL)
    ];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');

    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {now: NOW}));
});

test('Dnssec#verify NS RRset (lowercased embedded name in canonical RDATA)', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519, PacketTypes.NS);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);

    // Mixed-case input: canonical form must lowercase to match what the
    // signer used.
    const rrset = [
        new PacketResource(OWNER, new NS('NS1.Example.com'), PacketClass.IN, ORIGINAL_TTL),
        new PacketResource(OWNER, new NS('ns2.example.com'), PacketClass.IN, ORIGINAL_TTL),
    ];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');

    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {now: NOW}));
});

test('Dnssec#verify rejects mismatched key tag', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519);
    rrsig.keyTag = (Dnssec.computeKeyTag(dnskey) ^ 0xFFFF) & 0xFFFF;

    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');

    assert.equal(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {now: NOW}), false);
});

test('Dnssec#verify rejects tampered signature', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);

    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    const sig = crypto.sign(null, input, privateKey);
    sig[0] ^= 0x01;
    rrsig.signature = sig.toString('base64');

    assert.equal(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {now: NOW}), false);
});

test('Dnssec#verify rejects RRset mutated after signing', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);

    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');

    const tampered = [buildA('192.0.2.99')];
    assert.equal(Dnssec.verifyRrsig(OWNER, tampered, rrsig, dnskey, {now: NOW}), false);
});

test('Dnssec#verify rejects signature outside validity window', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);

    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');

    // Year 2200 — well past expiration but signature is still
    // cryptographically valid. The window check should catch it.
    const longAfter = 7258118400;
    assert.equal(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {now: longAfter}), false);
});

test('Dnssec#verify accepts expired signature when skipValidityWindow', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);

    const rrset = [buildA('192.0.2.1')];
    const input = Dnssec.buildSigningInput(OWNER, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');

    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {skipValidityWindow: true}));
});

test('Dnssec#verifyDs round-trip (SHA-256 digest)', () => {
    const {publicKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const owner = 'sub.example.com';

    const ds = new DS(
        Dnssec.computeKeyTag(dnskey),
        DnssecAlgorithm.ED25519,
        DnssecDigest.SHA256,
        Dnssec.computeDsDigest(owner, dnskey, DnssecDigest.SHA256)
    );

    assert.ok(Dnssec.verifyDs(owner, dnskey, ds));
});

test('Dnssec#verifyDs rejects mismatched digest', () => {
    const {publicKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);

    const ds = new DS(
        Dnssec.computeKeyTag(dnskey),
        DnssecAlgorithm.ED25519,
        DnssecDigest.SHA256,
        '00'.repeat(32)
    );

    assert.equal(Dnssec.verifyDs('example.com', dnskey, ds), false);
});

test('Dnssec#computeKeyTag matches RFC 4034 Appendix B reference', () => {
    // Hand-traceable fixture: flags=257, protocol=3, algorithm=8,
    // key="AAEC" (base64 → bytes 00 01 02). RDATA bytes are
    // [01 01 03 08 00 01 02]. Key tag is the folded sum of 16-bit
    // big-endian words (last byte zero-extended for an odd-length RDATA):
    //   0x0101 + 0x0308 + 0x0001 + 0x0200 = 0x060A
    const dnskey = new DNSKEY(257, 3, 8, 'AAEC');
    assert.equal(Dnssec.computeKeyTag(dnskey), 0x060A);
});

test('Dnssec#verifyRrsig throws on unsupported algorithm', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    dnskey.algorithm = 5; // RSA/SHA-1 — out of scope
    const rrsig = buildRrsig(5);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);

    const rrset = [buildA('192.0.2.1')];
    rrsig.signature = crypto.sign(null, Buffer.from('x'), privateKey).toString('base64');

    assert.throws(() => Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {now: NOW}));
});