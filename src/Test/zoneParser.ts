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
import {A} from '../Packet/Types/A.js';
import {AAAA} from '../Packet/Types/AAAA.js';
import {CAA} from '../Packet/Types/CAA.js';
import {CNAME} from '../Packet/Types/CNAME.js';
import {DNAME} from '../Packet/Types/DNAME.js';
import {MX} from '../Packet/Types/MX.js';
import {NS} from '../Packet/Types/NS.js';
import {PTR} from '../Packet/Types/PTR.js';
import {SOA} from '../Packet/Types/SOA.js';
import {SRV} from '../Packet/Types/SRV.js';
import {TXT} from '../Packet/Types/TXT.js';
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