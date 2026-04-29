import assert from 'assert';
import * as crypto from 'crypto';
import {Dnssec, DnssecAlgorithm} from '../Lib/Dnssec.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {Zone} from '../Packet/Zone.js';
import {NegativeProof} from '../Resolver/NegativeProof.js';
import {test} from './test.js';

const SIGN_INCEPTION = '20240101000000';
const SIGN_EXPIRATION = '20300101000000';

/**
 * Build the standard test zone for negative proofs. Owner names are
 * `example.com` apex, `mail`, `ns1`, `www`, `*.wild` — `signZone` will
 * synthesize an NSEC chain covering exactly those names plus the
 * wildcard slot.
 */
const buildZone = (): Zone => {
    return Zone.fromZoneFile(`
        $ORIGIN example.com.
        $TTL 3600
        @       IN SOA  ns1 admin (1 7200 3600 1209600 3600)
        @       IN NS   ns1
        @       IN MX   10 mail
        ns1     IN A    192.0.2.1
        mail    IN A    192.0.2.2
        www     IN A    192.0.2.3
    `.replace(/^ {8}/gmu, ''));
};

const generateCsk = (): {dnskey: ReturnType<typeof Dnssec.publicKeyToDnskey>; privateKey: crypto.KeyObject;} => {
    const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');
    return {
        dnskey: Dnssec.publicKeyToDnskey(publicKey, DnssecAlgorithm.ED25519),
        privateKey: privateKey
    };
};

const signedZoneNsec = (): {records: PacketResource[]; nsecs: PacketResource[];} => {
    const csk = generateCsk();
    const zone = buildZone();

    const result = Dnssec.signZone(zone, {
        ksk: csk,
        zsk: csk,
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
        nsec: true
    });

    const nsecs = result.records.filter((r) => r.packetType.type === PacketTypes.NSEC);
    return {records: result.records, nsecs: nsecs};
};

const signedZoneNsec3 = (): {records: PacketResource[]; nsec3s: PacketResource[];} => {
    const csk = generateCsk();
    const zone = buildZone();

    const result = Dnssec.signZone(zone, {
        ksk: csk,
        zsk: csk,
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
        nsec3: {salt: 'aabbcc', iterations: 0}
    });

    const nsec3s = result.records.filter((r) => r.packetType.type === PacketTypes.NSEC3);
    return {records: result.records, nsec3s: nsec3s};
};

/* ----------------------------------------------------------------------- */
/*  NSEC                                                                    */
/* ----------------------------------------------------------------------- */

test('NegativeProof#verifyNxdomainNsec accepts a real proof for an absent name', () => {
    const {nsecs} = signedZoneNsec();
    // 'absent.example.com' isn't in the zone.
    assert.equal(NegativeProof.verifyNxdomainNsec('absent.example.com', 'example.com', nsecs), true);
});

test('NegativeProof#verifyNxdomainNsec rejects a name that exists in the zone', () => {
    const {nsecs} = signedZoneNsec();
    // www.example.com is present, so an NSEC at owner == www exists with bitmap.
    // The function should refuse: an exact NSEC match contradicts NXDOMAIN.
    assert.equal(NegativeProof.verifyNxdomainNsec('www.example.com', 'example.com', nsecs), false);
});

test('NegativeProof#verifyNxdomainNsec rejects when no NSEC supplied', () => {
    assert.equal(NegativeProof.verifyNxdomainNsec('absent.example.com', 'example.com', []), false);
});

test('NegativeProof#verifyNodataNsec accepts when type is missing from bitmap at qname', () => {
    const {nsecs} = signedZoneNsec();
    // www.example.com has only A; ask for MX → NODATA.
    assert.equal(NegativeProof.verifyNodataNsec('www.example.com', PacketTypes.MX, nsecs), true);
});

test('NegativeProof#verifyNodataNsec rejects when type is present in bitmap', () => {
    const {nsecs} = signedZoneNsec();
    // www.example.com has A; the bitmap includes A, so NODATA proof is wrong.
    assert.equal(NegativeProof.verifyNodataNsec('www.example.com', PacketTypes.A, nsecs), false);
});

test('NegativeProof#verifyNodataNsec rejects when qname is not in any NSEC owner', () => {
    const {nsecs} = signedZoneNsec();
    assert.equal(NegativeProof.verifyNodataNsec('absent.example.com', PacketTypes.A, nsecs), false);
});

test('NegativeProof#closestEncloserNsec finds the deepest matching ancestor', () => {
    const {nsecs} = signedZoneNsec();
    // For 'foo.bar.example.com', the closest encloser is the apex 'example.com'.
    const ce = NegativeProof.closestEncloserNsec('foo.bar.example.com', 'example.com', nsecs);
    assert.equal(ce, 'example.com');
});

test('NegativeProof#closestEncloserNsec returns the zone apex when no NSEC owner is closer', () => {
    const {nsecs} = signedZoneNsec();
    const ce = NegativeProof.closestEncloserNsec('newchild.example.com', 'example.com', nsecs);
    assert.equal(ce, 'example.com');
});

/* ----------------------------------------------------------------------- */
/*  NSEC3                                                                   */
/* ----------------------------------------------------------------------- */

test('NegativeProof#verifyNxdomainNsec3 accepts a real closest-encloser proof', () => {
    const {nsec3s} = signedZoneNsec3();
    // 'absent.example.com' isn't in the zone — the chain proves it.
    assert.equal(NegativeProof.verifyNxdomainNsec3('absent.example.com', 'example.com', nsec3s), true);
});

test('NegativeProof#verifyNxdomainNsec3 rejects when no NSEC3 supplied', () => {
    assert.equal(NegativeProof.verifyNxdomainNsec3('absent.example.com', 'example.com', []), false);
});

test('NegativeProof#verifyNodataNsec3 accepts when bitmap omits qtype', () => {
    const {nsec3s} = signedZoneNsec3();
    // www.example.com has only A; asking for MX is NODATA.
    assert.equal(NegativeProof.verifyNodataNsec3('www.example.com', PacketTypes.MX, 'example.com', nsec3s), true);
});

test('NegativeProof#verifyNodataNsec3 rejects when bitmap includes qtype', () => {
    const {nsec3s} = signedZoneNsec3();
    assert.equal(NegativeProof.verifyNodataNsec3('www.example.com', PacketTypes.A, 'example.com', nsec3s), false);
});