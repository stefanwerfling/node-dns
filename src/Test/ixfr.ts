import assert from 'assert';
import {AddressInfo} from 'net';
import {IxfrClient} from '../Client/IxfrClient.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {SOA} from '../Packet/Types/SOA.js';
import {Zone, ZoneChangeSet} from '../Packet/Zone.js';
import {DnsServer} from '../Server/DnsServer.js';
import {test} from './test.js';

const ZONE_V1 = `$ORIGIN example.com.
$TTL 3600
@   IN SOA ns1 admin (
        1
        7200
        3600
        1209600
        3600 )
@   IN NS  ns1
www IN A   192.0.2.1
`;

const ZONE_V2 = `$ORIGIN example.com.
$TTL 3600
@   IN SOA ns1 admin (
        2
        7200
        3600
        1209600
        3600 )
@   IN NS  ns1
www IN A   192.0.2.99
mail IN A  192.0.2.100
`;

const buildSoa = (serial: number): SOA => {
    return new SOA('ns1.example.com', 'admin.example.com', serial, 7200, 3600, 1209600, 3600);
};

const buildSoaResource = (serial: number): PacketResource => {
    return new PacketResource('example.com', buildSoa(serial), PacketClass.IN, 3600);
};

test('ixfr#makeQuery puts current SOA in authority section (RFC 1995 §3)', () => {
    const buf = IxfrClient.makeQuery('example.com', buildSoa(1));
    const parsed = Packet.parse(buf);

    assert.equal(parsed.questions[0].name, 'example.com');
    assert.equal(parsed.questions[0].type, PacketTypes.IXFR);
    assert.equal(parsed.questions[0].class, PacketClass.IN);
    assert.equal(parsed.authorities.length, 1);
    assert.equal(parsed.authorities[0].packetType.type, PacketTypes.SOA);
    assert.equal((parsed.authorities[0].packetType as SOA).serial, 1);
});

test('ixfr#zone.toIxfrPackets returns single SOA when serial matches', () => {
    const zone = Zone.fromZoneFile(ZONE_V1);
    const query = Packet.parse(IxfrClient.makeQuery('example.com', buildSoa(1)));

    const [response] = zone.toIxfrPackets(query);

    assert.equal(response.answers.length, 1);
    assert.equal(response.answers[0].packetType.type, PacketTypes.SOA);
    assert.equal((response.answers[0].packetType as SOA).serial, 1);
});

test('ixfr#zone.toIxfrPackets falls back to AXFR without history', () => {
    const zone = Zone.fromZoneFile(ZONE_V2);
    const query = Packet.parse(IxfrClient.makeQuery('example.com', buildSoa(1)));

    const [response] = zone.toIxfrPackets(query);

    // AXFR fallback: opening SOA, all records, closing SOA → SOA at start AND end
    // with no interior SOA other than those two.
    const middle = response.answers.slice(1, -1);
    const interiorSoaCount = middle.filter((r) => r.packetType.type === PacketTypes.SOA).length;
    assert.equal(interiorSoaCount, 0);
    assert.equal(response.answers.length, zone.records.length + 1);
});

test('ixfr#zone.toIxfrPackets emits incremental diff when history covers gap', () => {
    const zone = Zone.fromZoneFile(ZONE_V2);
    const oldSoa = buildSoaResource(1);
    const newSoa = zone.soa();
    const deleted = new PacketResource('www.example.com', new A('192.0.2.1'), PacketClass.IN, 3600);
    const addedWww = new PacketResource('www.example.com', new A('192.0.2.99'), PacketClass.IN, 3600);
    const addedMail = new PacketResource('mail.example.com', new A('192.0.2.100'), PacketClass.IN, 3600);

    const history: ZoneChangeSet[] = [{
        fromSerial: 1,
        toSerial: 2,
        fromSoa: oldSoa,
        toSoa: newSoa,
        deletions: [deleted],
        additions: [addedWww, addedMail],
    }];

    const query = Packet.parse(IxfrClient.makeQuery('example.com', buildSoa(1)));
    const [response] = zone.toIxfrPackets(query, {history: history});

    // Expected layout:
    //   SOA(2)   — current
    //   SOA(1)   — from
    //   deleted www A 192.0.2.1
    //   SOA(2)   — to
    //   added www A 192.0.2.99
    //   added mail A 192.0.2.100
    //   SOA(2)   — closing
    assert.equal(response.answers.length, 7);
    assert.equal((response.answers[0].packetType as SOA).serial, 2);
    assert.equal((response.answers[1].packetType as SOA).serial, 1);
    assert.equal(((response.answers[2].packetType) as A).address, '192.0.2.1');
    assert.equal((response.answers[3].packetType as SOA).serial, 2);
    assert.equal(((response.answers[4].packetType) as A).address, '192.0.2.99');
    assert.equal(((response.answers[5].packetType) as A).address, '192.0.2.100');
    assert.equal((response.answers[6].packetType as SOA).serial, 2);
});

test('ixfr#client end-to-end no-change response', async() => {
    const zone = Zone.fromZoneFile(ZONE_V1);

    const server = new DnsServer({
        tcp: true,
        handle: (request, send): void => {
            send(zone.toIxfrPackets(request));
        },
    });

    const addresses = await server.listen();
    const port = (addresses.tcp as AddressInfo).port;

    const transfer = IxfrClient.request({dns: '127.0.0.1', port: port});
    const result = await transfer('example.com', buildSoa(1));

    assert.equal(result.type, 'noChange');

    if (result.type === 'noChange') {
        assert.equal((result.soa.packetType as SOA).serial, 1);
    }

    await server.close();
});

test('ixfr#client end-to-end AXFR fallback', async() => {
    const zone = Zone.fromZoneFile(ZONE_V2);

    const server = new DnsServer({
        tcp: true,
        handle: (request, send): void => {
            send(zone.toIxfrPackets(request));   // no history → AXFR fallback
        },
    });

    const addresses = await server.listen();
    const port = (addresses.tcp as AddressInfo).port;

    const transfer = IxfrClient.request({dns: '127.0.0.1', port: port});
    const result = await transfer('example.com', buildSoa(1));

    assert.equal(result.type, 'fullAxfr');

    if (result.type === 'fullAxfr') {
        assert.equal((result.soa.packetType as SOA).serial, 2);
        // records = answers without opening/closing SOA
        assert.equal(result.records.length, zone.records.length - 1);
    }

    await server.close();
});

test('ixfr#client end-to-end incremental response', async() => {
    const zone = Zone.fromZoneFile(ZONE_V2);
    const oldSoa = buildSoaResource(1);
    const newSoa = zone.soa();
    const history: ZoneChangeSet[] = [{
        fromSerial: 1,
        toSerial: 2,
        fromSoa: oldSoa,
        toSoa: newSoa,
        deletions: [new PacketResource('www.example.com', new A('192.0.2.1'), PacketClass.IN, 3600)],
        additions: [
            new PacketResource('www.example.com', new A('192.0.2.99'), PacketClass.IN, 3600),
            new PacketResource('mail.example.com', new A('192.0.2.100'), PacketClass.IN, 3600),
        ],
    }];

    const server = new DnsServer({
        tcp: true,
        handle: (request, send): void => {
            send(zone.toIxfrPackets(request, {history: history}));
        },
    });

    const addresses = await server.listen();
    const port = (addresses.tcp as AddressInfo).port;

    const transfer = IxfrClient.request({dns: '127.0.0.1', port: port});
    const result = await transfer('example.com', buildSoa(1));

    assert.equal(result.type, 'incremental');

    if (result.type === 'incremental') {
        assert.equal((result.currentSoa.packetType as SOA).serial, 2);
        assert.equal(result.diffs.length, 1);

        const diff = result.diffs[0];
        assert.equal(diff.fromSerial, 1);
        assert.equal(diff.toSerial, 2);
        assert.equal(diff.deletions.length, 1);
        assert.equal((diff.deletions[0].packetType as A).address, '192.0.2.1');
        assert.equal(diff.additions.length, 2);
        assert.equal((diff.additions[0].packetType as A).address, '192.0.2.99');
        assert.equal((diff.additions[1].packetType as A).address, '192.0.2.100');
    }

    await server.close();
});

test('ixfr#client end-to-end multi-step incremental chain', async() => {
    const zone = Zone.fromZoneFile(ZONE_V2);
    const soa1 = buildSoaResource(1);
    const soa2 = buildSoaResource(2);

    // Two contiguous change sets: 1 → 2 → 3 (current zone is at serial 2 here,
    // so we'll cap with another 2→3 changeset using a re-built zone).
    // Simpler: history {1→2}, then update zone to serial 3 and add {2→3}.
    // For this test use serial 1→2 chain only (single step) but verify the
    // server's _stitchChain works with multi-step setups by creating two
    // small change sets that walk 1→2→3.
    const intermediate = new PacketResource('example.com', new SOA(
        'ns1.example.com', 'admin.example.com', 3, 7200, 3600, 1209600, 3600,
    ), PacketClass.IN, 3600);

    // Mutate the zone in place to current serial 3.
    zone.records = zone.records.map((r) => r === zone.soa() ? intermediate : r);

    const history: ZoneChangeSet[] = [
        {
            fromSerial: 1,
            toSerial: 2,
            fromSoa: soa1,
            toSoa: soa2,
            deletions: [new PacketResource('www.example.com', new A('192.0.2.1'), PacketClass.IN, 3600)],
            additions: [new PacketResource('www.example.com', new A('192.0.2.99'), PacketClass.IN, 3600)],
        },
        {
            fromSerial: 2,
            toSerial: 3,
            fromSoa: soa2,
            toSoa: intermediate,
            deletions: [],
            additions: [new PacketResource('mail.example.com', new A('192.0.2.100'), PacketClass.IN, 3600)],
        },
    ];

    const server = new DnsServer({
        tcp: true,
        handle: (request, send): void => {
            send(zone.toIxfrPackets(request, {history: history}));
        },
    });

    const addresses = await server.listen();
    const port = (addresses.tcp as AddressInfo).port;

    const transfer = IxfrClient.request({dns: '127.0.0.1', port: port});
    const result = await transfer('example.com', buildSoa(1));

    assert.equal(result.type, 'incremental');

    if (result.type === 'incremental') {
        assert.equal(result.diffs.length, 2);
        assert.equal(result.diffs[0].fromSerial, 1);
        assert.equal(result.diffs[0].toSerial, 2);
        assert.equal(result.diffs[1].fromSerial, 2);
        assert.equal(result.diffs[1].toSerial, 3);
        assert.equal(result.diffs[1].additions.length, 1);
        assert.equal((result.diffs[1].additions[0].packetType as A).address, '192.0.2.100');
    }

    await server.close();
});