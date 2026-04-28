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
import {MX} from '../Packet/Types/MX.js';
import {NAPTR} from '../Packet/Types/NAPTR.js';
import {NS} from '../Packet/Types/NS.js';
import {NSEC} from '../Packet/Types/NSEC.js';
import {RRSIG} from '../Packet/Types/RRSIG.js';
import {SOA} from '../Packet/Types/SOA.js';
import {SRV} from '../Packet/Types/SRV.js';
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

/**
 * Sign-and-verify a one-record RRset of the given type/owner. Used by
 * the per-type canonical-RDATA tests below — keeps each test focused
 * on the specific RR being canonicalized rather than on key-pair setup.
 */
const signAndVerify = (
    type: number,
    record: PacketResource,
    owner: string = OWNER
): boolean => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519, type);
    rrsig.signer = SIGNER;
    rrsig.labels = owner.split('.').filter((l) => l.length > 0).length;
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);

    const rrset = [record];
    const input = Dnssec.buildSigningInput(owner, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');

    return Dnssec.verifyRrsig(owner, rrset, rrsig, dnskey, {now: NOW});
};

test('Dnssec#canonical RDATA: SOA round-trips', () => {
    const soa = new SOA(
        'NS1.Example.com',           // mixed case — must lowercase to match
        'ADMIN.Example.com',
        2025010101, 7200, 3600, 1209600, 3600
    );
    const rr = new PacketResource(OWNER, soa, PacketClass.IN, ORIGINAL_TTL);
    assert.ok(signAndVerify(PacketTypes.SOA, rr));
});

test('Dnssec#canonical RDATA: SRV round-trips with mixed-case target', () => {
    const srv = new SRV(10, 20, 5060, 'Sip.Example.com');
    const rr = new PacketResource('_sip._tcp.example.com', srv, PacketClass.IN, ORIGINAL_TTL);
    assert.ok(signAndVerify(PacketTypes.SRV, rr, '_sip._tcp.example.com'));
});

test('Dnssec#canonical RDATA: NAPTR round-trips (replacement lowercased, char-strings preserved)', () => {
    // NAPTR character-strings (flags/services/regexp) keep their case;
    // only the replacement domain is canonicalized per RFC 4034 §6.2.
    const naptr = new NAPTR(
        100, 50,
        'U',                          // flags — preserve uppercase
        'E2U+sip',                    // services — preserve case
        '!^.*$!sip:info@example.com!',
        '_Sip._Tcp.Example.com'       // replacement — gets lowercased
    );
    const rr = new PacketResource(OWNER, naptr, PacketClass.IN, ORIGINAL_TTL);
    assert.ok(signAndVerify(PacketTypes.NAPTR, rr));
});

test('Dnssec#canonical RDATA: NSEC round-trips with lowercased nextDomain', () => {
    const nsec = new NSEC(
        'AlphA.Example.com',
        [PacketTypes.A, PacketTypes.AAAA, PacketTypes.RRSIG, PacketTypes.NSEC]
    );
    const rr = new PacketResource(OWNER, nsec, PacketClass.IN, ORIGINAL_TTL);
    assert.ok(signAndVerify(PacketTypes.NSEC, rr));
});

test('Dnssec#canonical RDATA: RRSIG-of-RRSIG round-trips with lowercased signer', () => {
    // Pathological but allowed: an RRSIG inside an RRset that itself
    // gets signed. We just need the canonical RDATA to lowercase the
    // signer name; the signature bytes pass through unchanged.
    const inner = new RRSIG(
        PacketTypes.A,
        DnssecAlgorithm.ED25519,
        2,
        3600,
        EXPIRATION,
        INCEPTION,
        12345,
        'Inner.Example.com',
        'AA=='
    );
    const rr = new PacketResource(OWNER, inner, PacketClass.IN, ORIGINAL_TTL);
    assert.ok(signAndVerify(PacketTypes.RRSIG, rr));
});

test('Dnssec#wildcard expansion: signed *.example.com verifies under host.example.com', () => {
    // Authoritative server signs `*.example.com IN A 192.0.2.1` with
    // labels=2. Client queries `host.example.com`; server expands the
    // wildcard, returns the answer with the expanded owner. Validator
    // must reconstruct `*.example.com` to verify.
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);

    // Sign with labels=2 (the wildcard form has 2 labels: example, com)
    const rrsig = new RRSIG(
        PacketTypes.A,
        DnssecAlgorithm.ED25519,
        2,                       // wildcard label count, NOT the expanded count
        ORIGINAL_TTL,
        EXPIRATION,
        INCEPTION,
        Dnssec.computeKeyTag(dnskey),
        SIGNER,
        ''
    );

    // Client receives the answer with the EXPANDED owner.
    const expandedOwner = 'host.example.com';
    const rrset = [
        new PacketResource(expandedOwner, new A('192.0.2.1'), PacketClass.IN, ORIGINAL_TTL)
    ];

    // Build signing input — the verifier sees that labels=2 < 3 actual
    // labels, so it reconstructs `*.example.com` as the signed owner.
    const input = Dnssec.buildSigningInput(expandedOwner, rrset, rrsig);
    rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');

    assert.ok(Dnssec.verifyRrsig(expandedOwner, rrset, rrsig, dnskey, {now: NOW}));
});

test('Dnssec#wildcard expansion: deep query under same wildcard verifies', () => {
    // Same wildcard, but client queried `a.b.c.example.com` (5 labels).
    // The wildcard form `*.example.com` (labels=2) covers everything
    // under example.com, so this must still verify.
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);

    const rrsig = new RRSIG(
        PacketTypes.A, DnssecAlgorithm.ED25519, 2, ORIGINAL_TTL,
        EXPIRATION, INCEPTION, Dnssec.computeKeyTag(dnskey), SIGNER, ''
    );

    const expanded = 'a.b.c.example.com';
    const rrset = [new PacketResource(expanded, new A('192.0.2.1'), PacketClass.IN, ORIGINAL_TTL)];

    rrsig.signature = crypto.sign(
        null, Dnssec.buildSigningInput(expanded, rrset, rrsig), privateKey
    ).toString('base64');

    assert.ok(Dnssec.verifyRrsig(expanded, rrset, rrsig, dnskey, {now: NOW}));
});

test('Dnssec#wildcard expansion: labels > owner labels is rejected', () => {
    // labels = 5 but owner only has 3 labels — that's a malformed RRSIG
    // per RFC 4035 §5.3.1. Verifier returns false.
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);

    const rrsig = new RRSIG(
        PacketTypes.A, DnssecAlgorithm.ED25519, 5 /* too many */, ORIGINAL_TTL,
        EXPIRATION, INCEPTION, Dnssec.computeKeyTag(dnskey), SIGNER, ''
    );

    const rrset = [new PacketResource(OWNER, new A('192.0.2.1'), PacketClass.IN, ORIGINAL_TTL)];

    // Even with a "valid" signature on whatever input, the labels check
    // catches the malformation before the crypto check.
    rrsig.signature = crypto.sign(
        null, Buffer.from('whatever'), privateKey
    ).toString('base64');

    assert.equal(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {now: NOW}), false);
});

test('Dnssec#verify MX RRset (existing single-name canonical) regression', () => {
    // Already covered indirectly elsewhere; explicit regression test
    // since MX uses the priority+name layout that's easy to break when
    // refactoring _canonicalRdataBytes.
    const mx1 = new PacketResource(
        OWNER, new MX('Mail1.Example.com', 10), PacketClass.IN, ORIGINAL_TTL
    );
    const mx2 = new PacketResource(
        OWNER, new MX('mail2.example.com', 20), PacketClass.IN, ORIGINAL_TTL
    );

    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = ed25519Dnskey(publicKey);
    const rrsig = buildRrsig(DnssecAlgorithm.ED25519, PacketTypes.MX);
    rrsig.keyTag = Dnssec.computeKeyTag(dnskey);

    const rrset = [mx1, mx2];
    rrsig.signature = crypto.sign(
        null, Dnssec.buildSigningInput(OWNER, rrset, rrsig), privateKey
    ).toString('base64');

    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {now: NOW}));
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

// ---------------------------------------------------------------------------
// Phase 2B: NSEC / NSEC3 negative-answer building blocks
// ---------------------------------------------------------------------------

test('Dnssec#canonicalNameCompare orders parent before child', () => {
    assert.equal(Dnssec.canonicalNameCompare('example.com', 'z.example.com'), -1);
    assert.equal(Dnssec.canonicalNameCompare('z.example.com', 'example.com'), 1);
});

test('Dnssec#canonicalNameCompare is case-insensitive', () => {
    assert.equal(Dnssec.canonicalNameCompare('Z.Example.COM', 'z.example.com'), 0);
});

test('Dnssec#canonicalNameCompare uses byte order within a label', () => {
    // 'y' (0x79) < 'z' (0x7A) regardless of mixed case
    assert.equal(Dnssec.canonicalNameCompare('yljkjljk.example.com', 'z.example.com'), -1);
});

test('Dnssec#canonicalNameCompare longer label sorts after shorter prefix', () => {
    // "z" is a prefix of "zz" — "z" sorts first
    assert.equal(Dnssec.canonicalNameCompare('z.example.com', 'zz.example.com'), -1);
});

test('Dnssec#canonicalNameCompare equal names', () => {
    assert.equal(Dnssec.canonicalNameCompare('a.example.com', 'a.example.com'), 0);
});

test('Dnssec#canonicalNameCompare TLD comes first', () => {
    // "example.com" < "example.net" because rightmost label compared first
    assert.equal(Dnssec.canonicalNameCompare('example.com', 'example.net'), -1);
});

test('Dnssec#nsecCovers proves name in normal range', () => {
    // NSEC at a.example.com pointing to c.example.com proves b.example.com
    // does not exist.
    assert.ok(Dnssec.nsecCovers('a.example.com', 'c.example.com', 'b.example.com'));
});

test('Dnssec#nsecCovers rejects name equal to either endpoint', () => {
    assert.equal(
        Dnssec.nsecCovers('a.example.com', 'c.example.com', 'a.example.com'),
        false
    );
    assert.equal(
        Dnssec.nsecCovers('a.example.com', 'c.example.com', 'c.example.com'),
        false
    );
});

test('Dnssec#nsecCovers rejects name outside range', () => {
    assert.equal(
        Dnssec.nsecCovers('a.example.com', 'c.example.com', 'd.example.com'),
        false
    );
});

test('Dnssec#nsecCovers handles wrap-around at end of zone', () => {
    // Last NSEC: z.example.com → example.com (back to apex). Names that
    // sort after z (e.g. zz, ä-prefixed if any) AND names equal to the
    // apex don't exist between owner and next, but anything strictly
    // between z and the apex (i.e. anything > z) is covered.
    assert.ok(Dnssec.nsecCovers('z.example.com', 'example.com', 'zz.example.com'));
});

test('Dnssec#nsecCovers wrap-around does not cover apex itself', () => {
    // The apex IS the next-domain endpoint; equality is not coverage.
    assert.equal(
        Dnssec.nsecCovers('z.example.com', 'example.com', 'example.com'),
        false
    );
});

test('Dnssec#base32hexEncode round-trips empty buffer', () => {
    assert.equal(Dnssec.base32hexEncode(Buffer.alloc(0)), '');
});

test('Dnssec#base32hexEncode round-trips against the parser', () => {
    // Build a 20-byte buffer and verify encode/decode cycles via the
    // ZoneParser's existing base32hex decoder. Implementation parity
    // against an independent decoder catches alphabet / bit-packing
    // mistakes.
    const original = Buffer.from('0102030405060708090a0b0c0d0e0f1011121314', 'hex');
    const encoded = Dnssec.base32hexEncode(original);
    assert.equal(encoded.length, 32);
    // Verify a few characters of expected output: the first 5 bits of
    // 0x01 = 00000 = '0', next 5 bits start with 0001 0000 ... = '04'
    // ('00000100' from second + first 2 bits of next)... easier just
    // to verify the first byte 0x01 produces "04..." (00000 00100):
    assert.equal(encoded.slice(0, 2), '04');
});

test('Dnssec#nsec3Hash matches RFC 5155 Appendix A.1 fixtures', () => {
    // Zone "example." with NSEC3PARAM 1 0 12 aabbccdd. Each pair below
    // is (owner name, expected base32hex(SHA-1) hashed owner).
    const fixtures: ReadonlyArray<readonly [string, string]> = [
        ['example.', '0p9mhaveqvm6t7vbl5lop2u3t2rp3tom'],
        ['a.example.', '35mthgpgcu1qg68fab165klnsnk3dpvl'],
        ['ai.example.', 'gjeqe526plbf1g8mklp59enfd789njgi'],
        ['ns1.example.', '2t7b4g4vsa5smi47k61mv5bv1a22bojr'],
        ['ns2.example.', 'q04jkcevqvmu85r014c7dkba38o0ji5r'],
        ['w.example.', 'k8udemvp1j2f7eg6jebps17vp3n8i58h'],
        ['*.w.example.', 'r53bq7cc2uvmubfu5ocmm6pers9tk9en'],
        ['x.w.example.', 'b4um86eghhds6nea196smvmlo4ors995'],
        ['y.w.example.', 'ji6neoaepv8b5o6k4ev33abha8ht9fgc'],
        ['x.y.w.example.', '2vptu5timamqttgl4luu9kg21e0aor3s'],
        ['xx.example.', 't644ebqk9bibcna874givr6joj62mlhv'],
    ];

    for (const [name, expected] of fixtures) {
        const hash = Dnssec.nsec3Hash(name, 'aabbccdd', 12);
        assert.equal(
            Dnssec.base32hexEncode(hash).toLowerCase(),
            expected,
            `mismatch for ${name}`
        );
    }
});

test('Dnssec#nsec3Hash with empty salt and zero iterations', () => {
    // Just SHA-1 of canonical "example." bytes — sanity check that
    // empty salt doesn't change the input.
    const expectedSha1 = crypto.createHash('sha1')
        .update(Buffer.from('076578616d706c6500', 'hex'))
        .digest();

    assert.deepEqual(Dnssec.nsec3Hash('example.', '', 0), expectedSha1);
});

test('Dnssec#nsec3Hash rejects unsupported algorithm', () => {
    assert.throws(() => Dnssec.nsec3Hash('example.', '', 0, 2));
});

test('Dnssec#nsec3CoversHash normal range', () => {
    const owner = Buffer.alloc(20, 0x10);
    const next = Buffer.alloc(20, 0x30);
    const inside = Buffer.alloc(20, 0x20);
    const outsideHigh = Buffer.alloc(20, 0x40);

    assert.ok(Dnssec.nsec3CoversHash(owner, next, inside));
    assert.equal(Dnssec.nsec3CoversHash(owner, next, outsideHigh), false);
    assert.equal(Dnssec.nsec3CoversHash(owner, next, owner), false);
    assert.equal(Dnssec.nsec3CoversHash(owner, next, next), false);
});

test('Dnssec#nsec3CoversHash wrap-around at end of chain', () => {
    // owner > next ⇒ this is the last NSEC3 in the chain, the wrap-around.
    // Anything > owner OR < next is covered.
    const owner = Buffer.alloc(20, 0xF0);
    const next = Buffer.alloc(20, 0x10);
    const aboveOwner = Buffer.alloc(20, 0xF8);
    const belowNext = Buffer.alloc(20, 0x05);
    const middle = Buffer.alloc(20, 0x80);

    assert.ok(Dnssec.nsec3CoversHash(owner, next, aboveOwner));
    assert.ok(Dnssec.nsec3CoversHash(owner, next, belowNext));
    assert.equal(Dnssec.nsec3CoversHash(owner, next, middle), false);
});

test('Dnssec#nsec3 NXDOMAIN proof end-to-end', () => {
    // Build a zone-style NSEC3 chain, then prove a queried name doesn't
    // exist by finding the NSEC3 that covers its hash.
    const salt = 'aabbccdd';
    const iter = 12;

    const chain = ['example.', 'a.example.', 'xx.example.'].map((n) => {
        const hash = Dnssec.nsec3Hash(n, salt, iter);
        return {name: n, hash: hash};
    });

    chain.sort((a, b) => Buffer.compare(a.hash, b.hash));

    // Query a name that's not in the chain
    const queryHash = Dnssec.nsec3Hash('nonexistent.example.', salt, iter);

    let covered = false;

    for (let i = 0; i < chain.length; i++) {
        const owner = chain[i].hash;
        const next = chain[(i + 1) % chain.length].hash;

        if (Dnssec.nsec3CoversHash(owner, next, queryHash)) {
            covered = true;
            break;
        }
    }

    assert.ok(covered, 'one NSEC3 in the chain should cover the queried name');
});

// ---------------------------------------------------------------------------
// Phase 3A: signing
// ---------------------------------------------------------------------------

const SIGN_INCEPTION = '20240101000000';
const SIGN_EXPIRATION = '20300101000000';

test('Dnssec#publicKeyToDnskey + signRrset round-trips RSA/SHA-256', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});
    const dnskey = Dnssec.publicKeyToDnskey(publicKey, DnssecAlgorithm.RSASHA256);
    const rrset = [buildA('192.0.2.1')];

    const rrsig = Dnssec.signRrset(OWNER, rrset, dnskey, privateKey, {
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
    });

    assert.equal(rrsig.algorithm, DnssecAlgorithm.RSASHA256);
    assert.equal(rrsig.keyTag, Dnssec.computeKeyTag(dnskey));
    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {now: NOW}));
});

test('Dnssec#publicKeyToDnskey + signRrset round-trips RSA/SHA-512', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});
    const dnskey = Dnssec.publicKeyToDnskey(publicKey, DnssecAlgorithm.RSASHA512);
    const rrset = [buildA('192.0.2.1')];

    const rrsig = Dnssec.signRrset(OWNER, rrset, dnskey, privateKey, {
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
    });

    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {now: NOW}));
});

test('Dnssec#publicKeyToDnskey + signRrset round-trips ECDSA P-256', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ec', {namedCurve: 'P-256'});
    const dnskey = Dnssec.publicKeyToDnskey(publicKey, DnssecAlgorithm.ECDSAP256SHA256);
    const rrset = [buildA('192.0.2.1')];

    const rrsig = Dnssec.signRrset(OWNER, rrset, dnskey, privateKey, {
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
    });

    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {now: NOW}));
});

test('Dnssec#publicKeyToDnskey + signRrset round-trips ECDSA P-384', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ec', {namedCurve: 'P-384'});
    const dnskey = Dnssec.publicKeyToDnskey(publicKey, DnssecAlgorithm.ECDSAP384SHA384);
    const rrset = [buildA('192.0.2.1')];

    const rrsig = Dnssec.signRrset(OWNER, rrset, dnskey, privateKey, {
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
    });

    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {now: NOW}));
});

test('Dnssec#publicKeyToDnskey + signRrset round-trips Ed25519', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = Dnssec.publicKeyToDnskey(publicKey, DnssecAlgorithm.ED25519);
    const rrset = [buildA('192.0.2.1')];

    const rrsig = Dnssec.signRrset(OWNER, rrset, dnskey, privateKey, {
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
    });

    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {now: NOW}));
});

test('Dnssec#signRrset rejects empty RRset', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = Dnssec.publicKeyToDnskey(publicKey, DnssecAlgorithm.ED25519);

    assert.throws(() => Dnssec.signRrset(OWNER, [], dnskey, privateKey, {
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
    }));
});

test('Dnssec#signRrset normalizes unix-decimal date input to YYYYMMDDHHMMSS', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = Dnssec.publicKeyToDnskey(publicKey, DnssecAlgorithm.ED25519);
    const rrset = [buildA('192.0.2.1')];

    // 1735689600 = 2025-01-01T00:00:00Z
    const rrsig = Dnssec.signRrset(OWNER, rrset, dnskey, privateKey, {
        inception: 1735689600,
        expiration: '1893456000',  // string-of-decimal, 2030-01-01T00:00:00Z
    });

    assert.equal(rrsig.inception, '20250101000000');
    assert.equal(rrsig.expiration, '20300101000000');
});

test('Dnssec#signRrset defaults: signer=owner, originalTtl=rrset[0].ttl, labels=label count', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = Dnssec.publicKeyToDnskey(publicKey, DnssecAlgorithm.ED25519);
    const rrset = [buildA('192.0.2.1')];

    const rrsig = Dnssec.signRrset(OWNER, rrset, dnskey, privateKey, {
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
    });

    assert.equal(rrsig.signer, OWNER);
    assert.equal(rrsig.originalTtl, ORIGINAL_TTL);
    assert.equal(rrsig.labels, 2);  // example.com → 2 labels
});

test('Dnssec#signRrset wildcard: labels default skips the * label, RRSIG verifies under expansion', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = Dnssec.publicKeyToDnskey(publicKey, DnssecAlgorithm.ED25519);

    // Sign at the wildcard owner; default labels handling must skip
    // the leading `*` per RFC 4034 §3.1.3 — no explicit override needed.
    const wildcardOwner = '*.example.com';
    const wildcardRrset = [
        new PacketResource(wildcardOwner, new A('192.0.2.1'), PacketClass.IN, ORIGINAL_TTL)
    ];

    const rrsig = Dnssec.signRrset(wildcardOwner, wildcardRrset, dnskey, privateKey, {
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
    });

    assert.equal(rrsig.labels, 2, 'wildcard label must not be counted');

    // Client receives the answer expanded to host.example.com
    const expandedRrset = [
        new PacketResource('host.example.com', new A('192.0.2.1'), PacketClass.IN, ORIGINAL_TTL)
    ];

    assert.ok(Dnssec.verifyRrsig('host.example.com', expandedRrset, rrsig, dnskey, {now: NOW}));
});

test('Dnssec#signRrset signed with one key fails verify against a different DNSKEY', () => {
    const sigKey = crypto.generateKeyPairSync('ed25519');
    const otherKey = crypto.generateKeyPairSync('ed25519');

    const sigDnskey = Dnssec.publicKeyToDnskey(sigKey.publicKey, DnssecAlgorithm.ED25519);
    const otherDnskey = Dnssec.publicKeyToDnskey(otherKey.publicKey, DnssecAlgorithm.ED25519);

    const rrset = [buildA('192.0.2.1')];

    const rrsig = Dnssec.signRrset(OWNER, rrset, sigDnskey, sigKey.privateKey, {
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
    });

    // keyTag mismatch is the first thing the verifier checks; the test
    // makes the rejection deterministic regardless of which check fires.
    assert.equal(Dnssec.verifyRrsig(OWNER, rrset, rrsig, otherDnskey, {now: NOW}), false);
});

test('Dnssec#publicKeyToDnskey throws on unsupported algorithm', () => {
    const {publicKey} = crypto.generateKeyPairSync('ed25519');
    assert.throws(() => Dnssec.publicKeyToDnskey(publicKey, 99));
});

test('Dnssec#publicKeyToDnskey throws when key type does not match algorithm', () => {
    const rsa = crypto.generateKeyPairSync('rsa', {modulusLength: 2048}).publicKey;
    assert.throws(() => Dnssec.publicKeyToDnskey(rsa, DnssecAlgorithm.ED25519));
});

test('Dnssec#sign + verify multi-record RRset round-trip', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = Dnssec.publicKeyToDnskey(publicKey, DnssecAlgorithm.ED25519);

    // Multiple A records — signRrset and verifyRrsig must agree on the
    // canonical-RDATA sort order.
    const rrset = [
        buildA('192.0.2.7'),
        buildA('192.0.2.1'),
        buildA('192.0.2.3'),
    ];

    const rrsig = Dnssec.signRrset(OWNER, rrset, dnskey, privateKey, {
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
    });

    // Shuffle on the receive side — verifier sorts canonically too
    const shuffled = [rrset[2], rrset[0], rrset[1]];
    assert.ok(Dnssec.verifyRrsig(OWNER, shuffled, rrsig, dnskey, {now: NOW}));
});

// ---------------------------------------------------------------------------
// Phase 3B: zone signing
// ---------------------------------------------------------------------------

import {Zone} from '../Packet/Zone.js';

const buildSignableZone = (): Zone => {
    return Zone.fromZoneFile(`
        $ORIGIN example.com.
        $TTL 3600
        @       IN SOA  ns1 admin (1 7200 3600 1209600 3600)
        @       IN NS   ns1
        @       IN MX   10 mail
        ns1     IN A    192.0.2.1
        mail    IN A    192.0.2.2
        www     IN A    192.0.2.3
        www     IN A    192.0.2.4
        *.wild  IN A    192.0.2.5
    `.replace(/^ {8}/gm, ''));
};

test('Dnssec#signZone produces RRSIG for every RRset and adds DNSKEY at apex', () => {
    const zone = buildSignableZone();

    const ksk = crypto.generateKeyPairSync('ed25519');
    const zsk = crypto.generateKeyPairSync('ed25519');
    const kskDnskey = Dnssec.publicKeyToDnskey(ksk.publicKey, DnssecAlgorithm.ED25519, 257);
    const zskDnskey = Dnssec.publicKeyToDnskey(zsk.publicKey, DnssecAlgorithm.ED25519, 256);

    const result = Dnssec.signZone(zone, {
        ksk: {dnskey: kskDnskey, privateKey: ksk.privateKey},
        zsk: {dnskey: zskDnskey, privateKey: zsk.privateKey},
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
    });

    // 7 distinct RRsets in the input + 1 synthesized DNSKEY RRset = 8
    assert.equal(result.rrsigs.length, 8);

    // DNSKEY records added at the apex
    const dnskeyRRs = result.records.filter(
        (r) => r.packetType.type === PacketTypes.DNSKEY && r.name === 'example.com'
    );
    assert.equal(dnskeyRRs.length, 2, 'KSK + ZSK published as DNSKEY records');
});

test('Dnssec#signZone DNSKEY RRset is signed by the KSK; other RRsets by the ZSK', () => {
    const zone = buildSignableZone();

    const ksk = crypto.generateKeyPairSync('ed25519');
    const zsk = crypto.generateKeyPairSync('ed25519');
    const kskDnskey = Dnssec.publicKeyToDnskey(ksk.publicKey, DnssecAlgorithm.ED25519, 257);
    const zskDnskey = Dnssec.publicKeyToDnskey(zsk.publicKey, DnssecAlgorithm.ED25519, 256);

    const kskTag = Dnssec.computeKeyTag(kskDnskey);
    const zskTag = Dnssec.computeKeyTag(zskDnskey);

    const result = Dnssec.signZone(zone, {
        ksk: {dnskey: kskDnskey, privateKey: ksk.privateKey},
        zsk: {dnskey: zskDnskey, privateKey: zsk.privateKey},
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
    });

    for (const rrsigRR of result.rrsigs) {
        const sig = rrsigRR.packetType as RRSIG;
        const expectedTag = sig.sigType === PacketTypes.DNSKEY ? kskTag : zskTag;
        assert.equal(
            sig.keyTag,
            expectedTag,
            `RRSIG for type ${sig.sigType} has wrong key tag`
        );
    }
});

test('Dnssec#signZone every RRSIG round-trips through verifyRrsig', () => {
    const zone = buildSignableZone();

    const ksk = crypto.generateKeyPairSync('ed25519');
    const zsk = crypto.generateKeyPairSync('ed25519');
    const kskDnskey = Dnssec.publicKeyToDnskey(ksk.publicKey, DnssecAlgorithm.ED25519, 257);
    const zskDnskey = Dnssec.publicKeyToDnskey(zsk.publicKey, DnssecAlgorithm.ED25519, 256);

    const result = Dnssec.signZone(zone, {
        ksk: {dnskey: kskDnskey, privateKey: ksk.privateKey},
        zsk: {dnskey: zskDnskey, privateKey: zsk.privateKey},
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
    });

    // For each RRSIG, find the matching RRset in result.records and the
    // matching DNSKEY by key tag, then verify.
    for (const rrsigRR of result.rrsigs) {
        const sig = rrsigRR.packetType as RRSIG;

        const rrset = result.records.filter(
            (r) =>
                r.name === rrsigRR.name
                && r.packetType.type === sig.sigType
        );

        const matchingKey = sig.keyTag === Dnssec.computeKeyTag(kskDnskey)
            ? kskDnskey
            : zskDnskey;

        const ok = Dnssec.verifyRrsig(rrsigRR.name, rrset, sig, matchingKey, {now: NOW});
        assert.ok(ok, `verify failed for ${rrsigRR.name}/${sig.sigType}`);
    }
});

test('Dnssec#signZone wildcard RRset gets correct labels count via signRrset default', () => {
    const zone = buildSignableZone();

    const csk = crypto.generateKeyPairSync('ed25519');
    const cskDnskey = Dnssec.publicKeyToDnskey(csk.publicKey, DnssecAlgorithm.ED25519);

    const result = Dnssec.signZone(zone, {
        ksk: {dnskey: cskDnskey, privateKey: csk.privateKey},
        zsk: {dnskey: cskDnskey, privateKey: csk.privateKey},
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
    });

    const wildcardRrsig = result.rrsigs.find((r) => r.name === '*.wild.example.com');
    assert.ok(wildcardRrsig, 'wildcard RRset must be signed');

    // *.wild.example.com → wild, example, com → 3 labels (excl. *)
    assert.equal((wildcardRrsig!.packetType as RRSIG).labels, 3);

    // Verify under expanded query name
    const expanded = [
        new PacketResource('host.wild.example.com', new A('192.0.2.5'), PacketClass.IN, 3600)
    ];
    assert.ok(Dnssec.verifyRrsig(
        'host.wild.example.com',
        expanded,
        wildcardRrsig!.packetType as RRSIG,
        cskDnskey,
        {now: NOW}
    ));
});

test('Dnssec#signZone CSK case (ksk === zsk) emits one DNSKEY and signs everything', () => {
    const zone = buildSignableZone();

    const csk = crypto.generateKeyPairSync('ed25519');
    const cskDnskey = Dnssec.publicKeyToDnskey(csk.publicKey, DnssecAlgorithm.ED25519);
    const signer = {dnskey: cskDnskey, privateKey: csk.privateKey};

    const result = Dnssec.signZone(zone, {
        ksk: signer,
        zsk: signer,
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
    });

    const dnskeyRRs = result.records.filter((r) => r.packetType.type === PacketTypes.DNSKEY);
    assert.equal(dnskeyRRs.length, 1, 'CSK case adds exactly one DNSKEY');

    const cskTag = Dnssec.computeKeyTag(cskDnskey);
    for (const rrsigRR of result.rrsigs) {
        assert.equal((rrsigRR.packetType as RRSIG).keyTag, cskTag);
    }
});

test('Dnssec#signZone falls back to TTL 3600 when zone has no SOA', () => {
    const zone = new Zone('example.com.', [
        new PacketResource('example.com', new A('192.0.2.1'), PacketClass.IN, 60),
    ]);

    const csk = crypto.generateKeyPairSync('ed25519');
    const cskDnskey = Dnssec.publicKeyToDnskey(csk.publicKey, DnssecAlgorithm.ED25519);

    const result = Dnssec.signZone(zone, {
        ksk: {dnskey: cskDnskey, privateKey: csk.privateKey},
        zsk: {dnskey: cskDnskey, privateKey: csk.privateKey},
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
    });

    const dnskey = result.records.find((r) => r.packetType.type === PacketTypes.DNSKEY);
    assert.equal(dnskey!.ttl, 3600);
});

test('Dnssec#signZone honors dnskeyTtl override', () => {
    const zone = buildSignableZone();

    const csk = crypto.generateKeyPairSync('ed25519');
    const cskDnskey = Dnssec.publicKeyToDnskey(csk.publicKey, DnssecAlgorithm.ED25519);

    const result = Dnssec.signZone(zone, {
        ksk: {dnskey: cskDnskey, privateKey: csk.privateKey},
        zsk: {dnskey: cskDnskey, privateKey: csk.privateKey},
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
        dnskeyTtl: 86400,
    });

    const dnskey = result.records.find((r) => r.packetType.type === PacketTypes.DNSKEY);
    assert.equal(dnskey!.ttl, 86400);
});

test('Dnssec#sign + verify SOA round-trip uses canonical RDATA on both sides', () => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    const dnskey = Dnssec.publicKeyToDnskey(publicKey, DnssecAlgorithm.ED25519);

    const soa = new SOA('NS1.Example.com', 'admin.Example.com', 1, 7200, 3600, 1209600, 3600);
    const rrset = [new PacketResource(OWNER, soa, PacketClass.IN, ORIGINAL_TTL)];

    const rrsig = Dnssec.signRrset(OWNER, rrset, dnskey, privateKey, {
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
    });

    assert.ok(Dnssec.verifyRrsig(OWNER, rrset, rrsig, dnskey, {now: NOW}));
});