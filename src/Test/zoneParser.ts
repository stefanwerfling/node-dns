import assert from 'assert';
import {ZoneParser} from '../Lib/ZoneParser.js';

/**
 * Strip the smallest leading-whitespace prefix common to all non-blank lines.
 * Lets tests indent zone strings for readability without breaking RFC 1035's
 * "leading whitespace ⇒ inherit owner name" rule.
 */
const dedent = (input: string): string => {
    const lines = input.split('\n');
    let min = Infinity;

    for (const ln of lines) {
        if (ln.trim().length === 0) {
            continue;
        }

        const match = ln.match(/^[ \t]*/);

        if (match) {
            min = Math.min(min, match[0].length);
        }
    }

    if (min === Infinity || min === 0) {
        return input;
    }

    return lines.map((ln) => ln.slice(min)).join('\n');
};
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {AAAA} from '../Packet/Types/AAAA.js';
import {CAA} from '../Packet/Types/CAA.js';
import {CDNSKEY} from '../Packet/Types/CDNSKEY.js';
import {CDS} from '../Packet/Types/CDS.js';
import {CNAME} from '../Packet/Types/CNAME.js';
import {DNAME} from '../Packet/Types/DNAME.js';
import {DNSKEY} from '../Packet/Types/DNSKEY.js';
import {DS} from '../Packet/Types/DS.js';
import {HTTPS} from '../Packet/Types/HTTPS.js';
import {MX} from '../Packet/Types/MX.js';
import {NAPTR} from '../Packet/Types/NAPTR.js';
import {NS} from '../Packet/Types/NS.js';
import {NSEC} from '../Packet/Types/NSEC.js';
import {NSEC3} from '../Packet/Types/NSEC3.js';
import {PTR} from '../Packet/Types/PTR.js';
import {RRSIG} from '../Packet/Types/RRSIG.js';
import {SOA} from '../Packet/Types/SOA.js';
import {SRV} from '../Packet/Types/SRV.js';
import {SSHFP} from '../Packet/Types/SSHFP.js';
import {SVCB} from '../Packet/Types/SVCB.js';
import {TLSA} from '../Packet/Types/TLSA.js';
import {TXT} from '../Packet/Types/TXT.js';
import {BufferReader} from '../Lib/BufferReader.js';
import {test} from './test.js';

test('zone#single A record with origin', () => {
    const {records, origin} = ZoneParser.parse('www 300 IN A 192.0.2.1', {origin: 'example.com'});
    assert.equal(origin, 'example.com.');
    assert.equal(records.length, 1);
    assert.equal(records[0].name, 'www.example.com');
    assert.equal(records[0].ttl, 300);
    assert.equal(records[0].class, PacketClass.IN);
    assert.equal((records[0].packetType as A).address, '192.0.2.1');
});

test('zone#$ORIGIN directive overrides default', () => {
    const zone = `
        $ORIGIN example.com.
        @   3600 IN SOA ns1 admin 1 7200 3600 1209600 3600
        ns1 3600 IN A   192.0.2.1
    `;
    const {records, origin} = ZoneParser.parse(dedent(zone));
    assert.equal(origin, 'example.com.');
    assert.equal(records[0].name, 'example.com');
    assert.equal(records[1].name, 'ns1.example.com');
});

test('zone#$TTL directive applies to records without TTL', () => {
    const zone = `
        $TTL 600
        $ORIGIN example.com.
        a IN A 1.1.1.1
        b IN A 2.2.2.2
    `;
    const {records} = ZoneParser.parse(dedent(zone));
    assert.equal(records[0].ttl, 600);
    assert.equal(records[1].ttl, 600);
});

test('zone#TTL inherited from previous record', () => {
    const zone = `
        $ORIGIN example.com.
        a 7200 IN A 1.1.1.1
        b      IN A 2.2.2.2
    `;
    const {records} = ZoneParser.parse(dedent(zone));
    assert.equal(records[0].ttl, 7200);
    assert.equal(records[1].ttl, 7200);
});

test('zone#name inherited from previous record (leading whitespace)', () => {
    const zone = `
        $ORIGIN example.com.
        www 60 IN A    192.0.2.1
                  IN A 192.0.2.2
    `;
    const {records} = ZoneParser.parse(dedent(zone));
    assert.equal(records.length, 2);
    assert.equal(records[0].name, 'www.example.com');
    assert.equal(records[1].name, 'www.example.com');
    assert.equal(records[1].ttl, 60);
});

test('zone#multi-line record via parens (SOA)', () => {
    const zone = `
        $ORIGIN example.com.
        @ 3600 IN SOA ns1.example.com. admin.example.com. (
            2024010101 ; serial
            7200       ; refresh
            3600       ; retry
            1209600    ; expire
            3600       ; minimum
        )
    `;
    const {records} = ZoneParser.parse(dedent(zone));
    assert.equal(records.length, 1);
    const soa = records[0].packetType as SOA;
    assert.equal(soa.primary, 'ns1.example.com');
    assert.equal(soa.admin, 'admin.example.com');
    assert.equal(soa.serial, 2024010101);
    assert.equal(soa.refresh, 7200);
    assert.equal(soa.retry, 3600);
    assert.equal(soa.expiration, 1209600);
    assert.equal(soa.minimum, 3600);
});

test('zone#@ resolves to current origin', () => {
    const {records} = ZoneParser.parse('@ IN A 192.0.2.1', {origin: 'foo.test.'});
    assert.equal(records[0].name, 'foo.test');
});

test('zone#absolute name (trailing dot) is not re-qualified', () => {
    const {records} = ZoneParser.parse('host.other.tld. 60 IN A 1.2.3.4', {origin: 'example.com.'});
    assert.equal(records[0].name, 'host.other.tld');
});

test('zone#comments and blank lines are ignored', () => {
    const zone = `
        ; this is a header comment

        $ORIGIN example.com. ; with trailing comment
        ; another comment

        host 60 IN A 192.0.2.1 ; record-level comment
    `;
    const {records} = ZoneParser.parse(dedent(zone));
    assert.equal(records.length, 1);
    assert.equal((records[0].packetType as A).address, '192.0.2.1');
});

test('zone#TXT quoted string preserves spaces and ; ', () => {
    const zone = `
        $ORIGIN example.com.
        host 60 IN TXT "hello; world with spaces"
    `;
    const {records} = ZoneParser.parse(dedent(zone));
    assert.equal((records[0].packetType as TXT).data, 'hello; world with spaces');
});

test('zone#TXT multiple character-strings', () => {
    const zone = `
        $ORIGIN example.com.
        host 60 IN TXT "v=spf1" "ip4:192.0.2.0/24" "-all"
    `;
    const {records} = ZoneParser.parse(dedent(zone));
    const txt = records[0].packetType as TXT;
    assert.deepEqual(txt.data, ['v=spf1', 'ip4:192.0.2.0/24', '-all']);
});

test('zone#TXT with escaped quote inside string', () => {
    const {records} = ZoneParser.parse(
        'host 60 IN TXT "she said \\"hi\\""',
        {origin: 'example.com.'}
    );
    assert.equal((records[0].packetType as TXT).data, 'she said "hi"');
});

test('zone#each common record type', () => {
    const zone = `
        $ORIGIN example.com.
        $TTL 300
        @       IN SOA   ns1 admin 1 7200 3600 1209600 3600
        @       IN NS    ns1
        @       IN MX    10 mail
        www     IN A     192.0.2.1
        www     IN AAAA  2001:db8::1
        alias   IN CNAME www
        1       IN PTR   www
        _http._tcp IN SRV 10 20 80 www
        @       IN CAA   0 issue "letsencrypt.org"
    `;
    const {records} = ZoneParser.parse(dedent(zone));
    assert.equal(records.length, 9);

    assert.ok(records[0].packetType instanceof SOA);
    assert.equal((records[1].packetType as NS).ns, 'ns1.example.com');
    const mx = records[2].packetType as MX;
    assert.equal(mx.priority, 10);
    assert.equal(mx.exchange, 'mail.example.com');
    assert.equal((records[3].packetType as A).address, '192.0.2.1');
    assert.equal((records[4].packetType as AAAA).address, '2001:db8::1');
    assert.equal((records[5].packetType as CNAME).domain, 'www.example.com');
    assert.equal((records[6].packetType as PTR).domain, 'www.example.com');
    const srv = records[7].packetType as SRV;
    assert.equal(srv.priority, 10);
    assert.equal(srv.weight, 20);
    assert.equal(srv.port, 80);
    assert.equal(srv.target, 'www.example.com');
    const caa = records[8].packetType as CAA;
    assert.equal(caa.flags, 0);
    assert.equal(caa.tag, 'issue');
    assert.equal(caa.value, 'letsencrypt.org');
});

test('zone#class is inherited and recognized', () => {
    const zone = `
        $ORIGIN example.com.
        a 60 IN A 1.1.1.1
        b 60    A 2.2.2.2
    `;
    const {records} = ZoneParser.parse(dedent(zone));
    assert.equal(records[0].class, PacketClass.IN);
    assert.equal(records[1].class, PacketClass.IN);
});

test('zone#DNAME redirects subtree', () => {
    const zone = `
        $ORIGIN example.com.
        old 60 IN DNAME new.example.net.
    `;
    const {records} = ZoneParser.parse(dedent(zone));
    assert.equal(records.length, 1);
    const dname = records[0].packetType as DNAME;
    assert.equal(records[0].name, 'old.example.com');
    assert.equal(dname.target, 'new.example.net');
});

test('zone#errors on unmatched parens', () => {
    assert.throws(() => ZoneParser.parse('@ IN SOA ns admin (1 2 3 4 5'));
});

test('zone#errors on unterminated quote', () => {
    assert.throws(() => ZoneParser.parse('host 60 IN TXT "missing close'));
});

test('zone#errors on unsupported record type', () => {
    assert.throws(() => ZoneParser.parse('@ IN AFSDB 1 host.', {origin: 'x.'}));
});

test('zone#errors on inheritance with no previous name', () => {
    assert.throws(() => ZoneParser.parse('     60 IN A 1.2.3.4', {origin: 'x.'}));
});

test('zone#errors on unknown directive', () => {
    assert.throws(() => ZoneParser.parse('$INCLUDE other.zone'));
});

test('zone#DNSKEY parses flags/protocol/algorithm and joins multi-token base64 key', () => {
    const zone = `
        $ORIGIN example.com.
        @ 3600 IN DNSKEY 256 3 8 (
            AwEAAcMnWBKLuvG/LwnPVykcmpvnntwxfshHlHRhlY0F
            3oz8AfbtBOIhKjQF6ttRPkmS )
    `;
    const {records} = ZoneParser.parse(dedent(zone));
    const dnskey = records[0].packetType as DNSKEY;
    assert.equal(dnskey.flags, 256);
    assert.equal(dnskey.protocol, 3);
    assert.equal(dnskey.algorithm, 8);
    assert.equal(
        dnskey.key,
        'AwEAAcMnWBKLuvG/LwnPVykcmpvnntwxfshHlHRhlY0F3oz8AfbtBOIhKjQF6ttRPkmS'
    );
});

test('zone#DS parses keyTag/algorithm/digestType and lowercases hex digest', () => {
    const zone = `
        $ORIGIN example.com.
        sub 3600 IN DS 31589 8 2 (
            AABBCCDDEEFF00112233445566778899
            AABBCCDDEEFF00112233445566778899 )
    `;
    const {records} = ZoneParser.parse(dedent(zone));
    const ds = records[0].packetType as DS;
    assert.equal(ds.keyTag, 31589);
    assert.equal(ds.algorithm, 8);
    assert.equal(ds.digestType, 2);
    assert.equal(
        ds.digest,
        'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899'
    );
});

test('zone#SSHFP parses algorithm/fpType/fingerprint', () => {
    const {records} = ZoneParser.parse(
        'host 60 IN SSHFP 1 1 BF6B6825D2977C511A475BBEFB88AAD54A92AC73',
        {origin: 'example.com.'}
    );
    const sshfp = records[0].packetType as SSHFP;
    assert.equal(sshfp.algorithm, 1);
    assert.equal(sshfp.fpType, 1);
    assert.equal(sshfp.fingerprint, 'bf6b6825d2977c511a475bbefb88aad54a92ac73');
});

test('zone#TLSA parses usage/selector/matching/cert', () => {
    const zone = `
        $ORIGIN example.com.
        _443._tcp.www 60 IN TLSA 3 1 1 (
            d2abde240d7cd3ee6b4b28c54df034b9
            7983a1d16e8a410e4561cb106618e971 )
    `;
    const {records} = ZoneParser.parse(dedent(zone));
    const tlsa = records[0].packetType as TLSA;
    assert.equal(tlsa.usage, 3);
    assert.equal(tlsa.selector, 1);
    assert.equal(tlsa.matchingType, 1);
    assert.equal(
        tlsa.certificate,
        'd2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971'
    );
});

test('zone#NAPTR parses with quoted character-strings', () => {
    const {records} = ZoneParser.parse(
        '@ 60 IN NAPTR 100 50 "s" "z3950+I2L+I2C" "" _z3950._tcp.example.com.',
        {origin: 'example.com.'}
    );
    const naptr = records[0].packetType as NAPTR;
    assert.equal(naptr.order, 100);
    assert.equal(naptr.preference, 50);
    assert.equal(naptr.flags, 's');
    assert.equal(naptr.services, 'z3950+I2L+I2C');
    assert.equal(naptr.regexp, '');
    assert.equal(naptr.replacement, '_z3950._tcp.example.com');
});

test('zone#NSEC parses next domain + type bit map mnemonics', () => {
    const {records} = ZoneParser.parse(
        '@ 3600 IN NSEC alpha.example.com. A NS SOA MX RRSIG NSEC DNSKEY',
        {origin: 'example.com.'}
    );
    const nsec = records[0].packetType as NSEC;
    assert.equal(nsec.nextDomain, 'alpha.example.com');
    assert.deepEqual(
        nsec.rdtypes,
        [
            PacketTypes.A,
            PacketTypes.NS,
            PacketTypes.SOA,
            PacketTypes.MX,
            PacketTypes.RRSIG,
            PacketTypes.NSEC,
            PacketTypes.DNSKEY,
        ]
    );
});

test('zone#NSEC accepts generic TYPEnnn mnemonic', () => {
    const {records} = ZoneParser.parse(
        '@ 60 IN NSEC next. TYPE65535 A',
        {origin: 'example.com.'}
    );
    const nsec = records[0].packetType as NSEC;
    assert.deepEqual(nsec.rdtypes, [65535, PacketTypes.A]);
});

test('zone#NSEC3 parses with empty salt (-) and base32hex next-hash', () => {
    // base32hex alphabet 0-9A-V; "09GM6" → 5 chars × 5 bits = 25 bits → 3 bytes
    // (with 1 trailing padding bit dropped per RFC 4648 §6).
    const zone = `
        $ORIGIN example.com.
        29gm6 60 IN NSEC3 1 0 10 - 09GM6 A RRSIG
    `;
    const {records} = ZoneParser.parse(dedent(zone));
    const nsec3 = records[0].packetType as NSEC3;
    assert.equal(nsec3.hashAlgorithm, 1);
    assert.equal(nsec3.flags, 0);
    assert.equal(nsec3.iterations, 10);
    assert.equal(nsec3.salt, '');
    assert.equal(nsec3.nextHashedOwner, '026163');
    assert.deepEqual(nsec3.rdtypes, [PacketTypes.A, PacketTypes.RRSIG]);
});

test('zone#NSEC3 lowercases hex salt', () => {
    const {records} = ZoneParser.parse(
        '@ 60 IN NSEC3 1 0 5 AABB 09GM6 NS',
        {origin: 'example.com.'}
    );
    const nsec3 = records[0].packetType as NSEC3;
    assert.equal(nsec3.salt, 'aabb');
});

test('zone#RRSIG parses presentation form and roundtrips through encode/decode', () => {
    const zone = `
        $ORIGIN example.com.
        @ 3600 IN RRSIG A 8 2 3600 (
            20260501000000 20260401000000 12345 example.com.
            ABCD== )
    `;
    const {records} = ZoneParser.parse(dedent(zone));
    const rrsig = records[0].packetType as RRSIG;
    assert.equal(rrsig.sigType, PacketTypes.A);
    assert.equal(rrsig.algorithm, 8);
    assert.equal(rrsig.labels, 2);
    assert.equal(rrsig.originalTtl, 3600);
    assert.equal(rrsig.expiration, '20260501000000');
    assert.equal(rrsig.inception, '20260401000000');
    assert.equal(rrsig.keyTag, 12345);
    assert.equal(rrsig.signer, 'example.com');
    assert.equal(rrsig.signature, 'ABCD==');

    // Encode → decode roundtrip
    const buf = rrsig.encode(records[0] as PacketResource);
    const reader = new BufferReader(buf);
    const rdlength = reader.read(16);
    const decoded = RRSIG.decode(reader, rdlength) as RRSIG;
    assert.equal(decoded.sigType, PacketTypes.A);
    assert.equal(decoded.algorithm, 8);
    assert.equal(decoded.labels, 2);
    assert.equal(decoded.originalTtl, 3600);
    assert.equal(decoded.expiration, '20260501000000');
    assert.equal(decoded.inception, '20260401000000');
    assert.equal(decoded.keyTag, 12345);
    assert.equal(decoded.signer, 'example.com');
});

test('zone#RRSIG accepts unix-timestamp inception/expiration', () => {
    // 1735689600 = 2025-01-01T00:00:00Z, 1738368000 = 2025-02-01T00:00:00Z
    const {records} = ZoneParser.parse(
        '@ 60 IN RRSIG A 8 2 3600 1738368000 1735689600 1 . AA==',
        {origin: 'example.com.'}
    );
    const rrsig = records[0].packetType as RRSIG;
    const buf = rrsig.encode(records[0] as PacketResource);
    const reader = new BufferReader(buf);
    const rdlength = reader.read(16);
    const decoded = RRSIG.decode(reader, rdlength) as RRSIG;
    assert.equal(decoded.expiration, '20250201000000');
    assert.equal(decoded.inception, '20250101000000');
});

test('zone#SVCB ServiceMode with alpn/port/ipv4hint/ipv6hint', () => {
    const {records} = ZoneParser.parse(
        '@ 60 IN SVCB 1 svc.example.net. alpn=h2,h3 port=8443 ipv4hint=192.0.2.1,192.0.2.2 ipv6hint=2001:db8::1',
        {origin: 'example.com.'}
    );
    const svcb = records[0].packetType as SVCB;
    assert.equal(svcb.priority, 1);
    assert.equal(svcb.target, 'svc.example.net');
    assert.deepEqual(svcb.params.alpn, ['h2', 'h3']);
    assert.equal(svcb.params.port, 8443);
    assert.deepEqual(svcb.params.ipv4hint, ['192.0.2.1', '192.0.2.2']);
    assert.deepEqual(svcb.params.ipv6hint, ['2001:db8::1']);
});

test('zone#SVCB AliasMode (priority 0, params absent)', () => {
    const {records} = ZoneParser.parse(
        '@ 60 IN SVCB 0 alias.example.net.',
        {origin: 'example.com.'}
    );
    const svcb = records[0].packetType as SVCB;
    assert.equal(svcb.priority, 0);
    assert.equal(svcb.target, 'alias.example.net');
});

test('zone#SVCB target "." resolves to empty (owner name)', () => {
    const {records} = ZoneParser.parse(
        '@ 60 IN SVCB 1 . alpn=h2',
        {origin: 'example.com.'}
    );
    const svcb = records[0].packetType as SVCB;
    assert.equal(svcb.target, '');
});

test('zone#SVCB no-default-alpn is a flag (no value)', () => {
    const {records} = ZoneParser.parse(
        '@ 60 IN SVCB 1 . alpn=h2 no-default-alpn',
        {origin: 'example.com.'}
    );
    const svcb = records[0].packetType as SVCB;
    assert.equal(svcb.params.noDefaultAlpn, true);
});

test('zone#SVCB dohpath= followed by quoted token', () => {
    const {records} = ZoneParser.parse(
        '@ 60 IN SVCB 1 . alpn=h2 dohpath="/dns-query{?dns}"',
        {origin: 'example.com.'}
    );
    const svcb = records[0].packetType as SVCB;
    assert.equal(svcb.params.dohpath, '/dns-query{?dns}');
});

test('zone#SVCB mandatory accepts mnemonic list', () => {
    const {records} = ZoneParser.parse(
        '@ 60 IN SVCB 1 . mandatory=alpn,port alpn=h2 port=443',
        {origin: 'example.com.'}
    );
    const svcb = records[0].packetType as SVCB;
    assert.deepEqual(svcb.params.mandatory, [1, 3]);
});

test('zone#SVCB unknown keyN= roundtrips through unknown[]', () => {
    const {records} = ZoneParser.parse(
        '@ 60 IN SVCB 1 . key99=hello',
        {origin: 'example.com.'}
    );
    const svcb = records[0].packetType as SVCB;
    assert.ok(svcb.params.unknown);
    assert.equal(svcb.params.unknown!.length, 1);
    assert.equal(svcb.params.unknown![0].key, 99);
    assert.equal(svcb.params.unknown![0].value.toString('utf8'), 'hello');
});

test('zone#HTTPS uses HTTPS subclass with same wire format', () => {
    const {records} = ZoneParser.parse(
        '@ 60 IN HTTPS 1 . alpn=h2,h3',
        {origin: 'example.com.'}
    );
    assert.ok(records[0].packetType instanceof HTTPS);
    const https = records[0].packetType as HTTPS;
    assert.equal(https.priority, 1);
    assert.deepEqual(https.params.alpn, ['h2', 'h3']);
});

test('zone#CDS parses with same fields as DS', () => {
    const {records} = ZoneParser.parse(
        '@ 3600 IN CDS 31589 8 2 AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899',
        {origin: 'example.com.'}
    );
    assert.ok(records[0].packetType instanceof CDS);
    const cds = records[0].packetType as CDS;
    assert.equal(cds.keyTag, 31589);
    assert.equal(cds.algorithm, 8);
    assert.equal(cds.digestType, 2);
    assert.equal(
        cds.digest,
        'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899'
    );
});

test('zone#CDS delete sentinel (0 0 0 00) parses', () => {
    const {records} = ZoneParser.parse(
        '@ 3600 IN CDS 0 0 0 00',
        {origin: 'example.com.'}
    );
    const cds = records[0].packetType as CDS;
    assert.equal(cds.keyTag, 0);
    assert.equal(cds.digest, '00');
});

test('zone#CDNSKEY parses with same fields as DNSKEY', () => {
    const zone = `
        $ORIGIN example.com.
        @ 3600 IN CDNSKEY 257 3 15 AAEC
    `;
    const {records} = ZoneParser.parse(dedent(zone));
    assert.ok(records[0].packetType instanceof CDNSKEY);
    const cdnskey = records[0].packetType as CDNSKEY;
    assert.equal(cdnskey.flags, 257);
    assert.equal(cdnskey.protocol, 3);
    assert.equal(cdnskey.algorithm, 15);
    assert.equal(cdnskey.key, 'AAEC');
});

test('zone#errors on missing RRSIG fields', () => {
    assert.throws(() => ZoneParser.parse(
        '@ 60 IN RRSIG A 8 2 3600 20260501000000 20260401000000 12345',
        {origin: 'example.com.'}
    ));
});

test('zone#errors on unknown SvcParamKey mnemonic', () => {
    assert.throws(() => ZoneParser.parse(
        '@ 60 IN SVCB 1 . totallymadeup=foo',
        {origin: 'example.com.'}
    ));
});