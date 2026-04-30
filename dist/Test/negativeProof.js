import assert from 'assert';
import * as crypto from 'crypto';
import { PacketClass } from '../Packet/PacketClass.js';
import { Dnssec, DnssecAlgorithm } from '../Lib/Dnssec.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { NSEC } from '../Packet/Types/NSEC.js';
import { NSEC3 } from '../Packet/Types/NSEC3.js';
import { Zone } from '../Packet/Zone.js';
import { NegativeProof } from '../Resolver/NegativeProof.js';
import { test } from './test.js';
const SIGN_INCEPTION = '20240101000000';
const SIGN_EXPIRATION = '20300101000000';
const buildZone = () => {
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
const generateCsk = () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    return {
        dnskey: Dnssec.publicKeyToDnskey(publicKey, DnssecAlgorithm.ED25519),
        privateKey: privateKey
    };
};
const signedZoneNsec = () => {
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
    return { records: result.records, nsecs: nsecs };
};
const signedZoneNsec3 = () => {
    const csk = generateCsk();
    const zone = buildZone();
    const result = Dnssec.signZone(zone, {
        ksk: csk,
        zsk: csk,
        inception: SIGN_INCEPTION,
        expiration: SIGN_EXPIRATION,
        nsec3: { salt: 'aabbcc', iterations: 0 }
    });
    const nsec3s = result.records.filter((r) => r.packetType.type === PacketTypes.NSEC3);
    return { records: result.records, nsec3s: nsec3s };
};
test('NegativeProof#verifyNxdomainNsec accepts a real proof for an absent name', () => {
    const { nsecs } = signedZoneNsec();
    assert.equal(NegativeProof.verifyNxdomainNsec('absent.example.com', 'example.com', nsecs), true);
});
test('NegativeProof#verifyNxdomainNsec rejects a name that exists in the zone', () => {
    const { nsecs } = signedZoneNsec();
    assert.equal(NegativeProof.verifyNxdomainNsec('www.example.com', 'example.com', nsecs), false);
});
test('NegativeProof#verifyNxdomainNsec rejects when no NSEC supplied', () => {
    assert.equal(NegativeProof.verifyNxdomainNsec('absent.example.com', 'example.com', []), false);
});
test('NegativeProof#verifyNodataNsec accepts when type is missing from bitmap at qname', () => {
    const { nsecs } = signedZoneNsec();
    assert.equal(NegativeProof.verifyNodataNsec('www.example.com', PacketTypes.MX, nsecs), true);
});
test('NegativeProof#verifyNodataNsec rejects when type is present in bitmap', () => {
    const { nsecs } = signedZoneNsec();
    assert.equal(NegativeProof.verifyNodataNsec('www.example.com', PacketTypes.A, nsecs), false);
});
test('NegativeProof#verifyNodataNsec rejects when qname is not in any NSEC owner', () => {
    const { nsecs } = signedZoneNsec();
    assert.equal(NegativeProof.verifyNodataNsec('absent.example.com', PacketTypes.A, nsecs), false);
});
test('NegativeProof#closestEncloserNsec finds the deepest matching ancestor', () => {
    const { nsecs } = signedZoneNsec();
    const ce = NegativeProof.closestEncloserNsec('foo.bar.example.com', 'example.com', nsecs);
    assert.equal(ce, 'example.com');
});
test('NegativeProof#closestEncloserNsec returns the zone apex when no NSEC owner is closer', () => {
    const { nsecs } = signedZoneNsec();
    const ce = NegativeProof.closestEncloserNsec('newchild.example.com', 'example.com', nsecs);
    assert.equal(ce, 'example.com');
});
test('NegativeProof#verifyNxdomainNsec3 accepts a real closest-encloser proof', () => {
    const { nsec3s } = signedZoneNsec3();
    assert.equal(NegativeProof.verifyNxdomainNsec3('absent.example.com', 'example.com', nsec3s), true);
});
test('NegativeProof#verifyNxdomainNsec3 rejects when no NSEC3 supplied', () => {
    assert.equal(NegativeProof.verifyNxdomainNsec3('absent.example.com', 'example.com', []), false);
});
test('NegativeProof#verifyNodataNsec3 accepts when bitmap omits qtype', () => {
    const { nsec3s } = signedZoneNsec3();
    assert.equal(NegativeProof.verifyNodataNsec3('www.example.com', PacketTypes.MX, 'example.com', nsec3s), true);
});
test('NegativeProof#verifyNodataNsec3 rejects when bitmap includes qtype', () => {
    const { nsec3s } = signedZoneNsec3();
    assert.equal(NegativeProof.verifyNodataNsec3('www.example.com', PacketTypes.A, 'example.com', nsec3s), false);
});
const NSEC3_DEFAULT_SALT = 'aabbcc';
const NSEC3_DEFAULT_ITER = 0;
const nsec3Rec = (delegationName, bitmapTypes, flags = 0, parentApex = 'com.') => {
    const ownerHashBuf = Dnssec.nsec3Hash(delegationName, NSEC3_DEFAULT_SALT, NSEC3_DEFAULT_ITER);
    const ownerLabel = Dnssec.base32hexEncode(ownerHashBuf).toLowerCase();
    const nextHashHex = Buffer.alloc(20, 0xff).toString('hex');
    const nsec3 = new NSEC3(1, flags, NSEC3_DEFAULT_ITER, NSEC3_DEFAULT_SALT, nextHashHex, bitmapTypes);
    return new PacketResource(`${ownerLabel}.${parentApex}`, nsec3, PacketClass.IN, 3600);
};
const nsec3CoverRec = (ownerHashBuf, nextHashBuf, flags, bitmapTypes, parentApex = 'com.') => {
    const ownerLabel = Dnssec.base32hexEncode(ownerHashBuf).toLowerCase();
    const nsec3 = new NSEC3(1, flags, NSEC3_DEFAULT_ITER, NSEC3_DEFAULT_SALT, nextHashBuf.toString('hex'), bitmapTypes);
    return new PacketResource(`${ownerLabel}.${parentApex}`, nsec3, PacketClass.IN, 3600);
};
test('NegativeProof#verifyInsecureDelegationNsec accepts NS-but-no-DS bitmap at owner', () => {
    const rec = new PacketResource('unsigned.com.', new NSEC('next.com.', [PacketTypes.NS, PacketTypes.RRSIG]), PacketClass.IN, 3600);
    assert.equal(NegativeProof.verifyInsecureDelegationNsec('unsigned.com.', [rec]), true);
});
test('NegativeProof#verifyInsecureDelegationNsec rejects when DS is in the bitmap', () => {
    const rec = new PacketResource('signed.com.', new NSEC('next.com.', [PacketTypes.NS, PacketTypes.DS, PacketTypes.RRSIG]), PacketClass.IN, 3600);
    assert.equal(NegativeProof.verifyInsecureDelegationNsec('signed.com.', [rec]), false);
});
test('NegativeProof#verifyInsecureDelegationNsec rejects an apex (SOA in bitmap) — not a delegation', () => {
    const rec = new PacketResource('apex.com.', new NSEC('next.com.', [PacketTypes.SOA, PacketTypes.NS, PacketTypes.RRSIG]), PacketClass.IN, 3600);
    assert.equal(NegativeProof.verifyInsecureDelegationNsec('apex.com.', [rec]), false);
});
test('NegativeProof#verifyInsecureDelegationNsec rejects when no NSEC matches the owner', () => {
    const rec = new PacketResource('other.com.', new NSEC('next.com.', [PacketTypes.NS, PacketTypes.RRSIG]), PacketClass.IN, 3600);
    assert.equal(NegativeProof.verifyInsecureDelegationNsec('unsigned.com.', [rec]), false);
});
test('NegativeProof#verifyInsecureDelegationNsec3 accepts a hash-match with NS-but-no-DS bitmap', () => {
    const rec = nsec3Rec('unsigned.com.', [PacketTypes.NS, PacketTypes.RRSIG]);
    assert.equal(NegativeProof.verifyInsecureDelegationNsec3('unsigned.com.', [rec]), true);
});
test('NegativeProof#verifyInsecureDelegationNsec3 rejects a hash-match with DS in bitmap', () => {
    const rec = nsec3Rec('signed.com.', [PacketTypes.NS, PacketTypes.DS, PacketTypes.RRSIG]);
    assert.equal(NegativeProof.verifyInsecureDelegationNsec3('signed.com.', [rec]), false);
});
test('NegativeProof#verifyInsecureDelegationNsec3 accepts opt-out cover for a non-existent NSEC3 owner', () => {
    const target = Dnssec.nsec3Hash('skipped.com.', NSEC3_DEFAULT_SALT, NSEC3_DEFAULT_ITER);
    const owner = Buffer.from(target);
    owner[19] = (owner[19] - 1) & 0xff;
    const next = Buffer.from(target);
    next[19] = (next[19] + 1) & 0xff;
    const rec = nsec3CoverRec(owner, next, 0x01, [PacketTypes.NS, PacketTypes.RRSIG]);
    assert.equal(NegativeProof.verifyInsecureDelegationNsec3('skipped.com.', [rec]), true);
});
test('NegativeProof#verifyInsecureDelegationNsec3 rejects opt-out cover when range does not include target', () => {
    const target = Dnssec.nsec3Hash('outside.com.', NSEC3_DEFAULT_SALT, NSEC3_DEFAULT_ITER);
    const owner = Buffer.alloc(20, 0x00);
    const next = Buffer.alloc(20, 0x01);
    if (target[0] <= 1) {
        target[0] = 0x80;
    }
    const rec = nsec3CoverRec(owner, next, 0x01, [PacketTypes.NS, PacketTypes.RRSIG]);
    assert.equal(NegativeProof.verifyInsecureDelegationNsec3('outside.com.', [rec]), false);
});
test('NegativeProof#verifyInsecureDelegationNsec3 rejects cover without opt-out flag', () => {
    const target = Dnssec.nsec3Hash('skipped.com.', NSEC3_DEFAULT_SALT, NSEC3_DEFAULT_ITER);
    const owner = Buffer.from(target);
    owner[19] = (owner[19] - 1) & 0xff;
    const next = Buffer.from(target);
    next[19] = (next[19] + 1) & 0xff;
    const rec = nsec3CoverRec(owner, next, 0x00, [PacketTypes.NS, PacketTypes.RRSIG]);
    assert.equal(NegativeProof.verifyInsecureDelegationNsec3('skipped.com.', [rec]), false);
});
//# sourceMappingURL=negativeProof.js.map