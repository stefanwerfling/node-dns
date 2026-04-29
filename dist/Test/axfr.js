import assert from 'assert';
import { AxfrClient } from '../Client/AxfrClient.js';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { Zone } from '../Packet/Zone.js';
import { DnsServer } from '../Server/DnsServer.js';
import { test } from './test.js';
const SAMPLE_ZONE = `$ORIGIN example.com.
$TTL 3600
@   IN SOA ns1 admin (
        2024010101
        7200
        3600
        1209600
        3600 )
@   IN NS  ns1
@   IN MX  10 mail
www IN A   192.0.2.1
mail IN A  192.0.2.2
`;
test('zone#fromZoneFile builds zone from text', () => {
    const zone = Zone.fromZoneFile(SAMPLE_ZONE);
    assert.equal(zone.origin, 'example.com.');
    assert.equal(zone.records.length, 5);
    assert.ok(zone.soa());
    assert.equal(zone.soaRdata().serial, 2024010101);
});
test('zone#soa throws when missing', () => {
    const zone = new Zone('example.com.', []);
    assert.throws(() => zone.soa());
});
test('zone#recordsOfType filters by type', () => {
    const zone = Zone.fromZoneFile(SAMPLE_ZONE);
    const aRecords = [...zone.recordsOfType(PacketTypes.A)];
    assert.equal(aRecords.length, 2);
    assert.equal(aRecords[0].packetType.address, '192.0.2.1');
    assert.equal(aRecords[1].packetType.address, '192.0.2.2');
});
test('zone#toAxfrPackets emits SOA-bracketed answer (RFC 5936 §2.2)', () => {
    const zone = Zone.fromZoneFile(SAMPLE_ZONE);
    const query = new Packet();
    query.header.id = 0x4242;
    query.questions.push(new PacketQuestion('example.com', PacketTypes.AXFR, PacketClass.IN));
    const packets = zone.toAxfrPackets(query);
    assert.equal(packets.length, 1);
    const resp = packets[0];
    assert.equal(resp.header.qr, 1);
    assert.equal(resp.header.aa, 1);
    assert.equal(resp.questions.length, 1);
    assert.equal(resp.questions[0].type, PacketTypes.AXFR);
    assert.equal(resp.answers.length, zone.records.length + 1);
    assert.equal(resp.answers[0].packetType.type, PacketTypes.SOA);
    assert.equal(resp.answers[resp.answers.length - 1].packetType.type, PacketTypes.SOA);
});
test('axfr#end-to-end via DnsServer + AxfrClient', async () => {
    const zone = Zone.fromZoneFile(SAMPLE_ZONE);
    const server = new DnsServer({
        tcp: true,
        handle: (request, send) => {
            const q = request.questions[0];
            assert.equal(q.type, PacketTypes.AXFR);
            send(zone.toAxfrPackets(request));
        },
    });
    const addresses = await server.listen();
    const port = addresses.tcp.port;
    const transfer = AxfrClient.request({ dns: '127.0.0.1', port: port });
    const result = await transfer('example.com');
    assert.equal(result.records.length, zone.records.length);
    assert.equal(result.soa.packetType.serial, 2024010101);
    assert.equal(result.records[0].packetType.type, PacketTypes.SOA);
    const types = result.records.map((r) => r.packetType.type).sort();
    const expected = zone.records.map((r) => r.packetType.type).sort();
    assert.deepEqual(types, expected);
    await server.close();
});
test('zone#toAxfrPackets splits when the response exceeds maxMessageSize', () => {
    const zone = Zone.fromZoneFile(SAMPLE_ZONE);
    const query = new Packet();
    query.header.id = 0xCAFE;
    query.questions.push(new PacketQuestion('example.com', PacketTypes.AXFR, PacketClass.IN));
    const packets = zone.toAxfrPackets(query, { maxMessageSize: 200 });
    assert.ok(packets.length >= 2, `expected ≥2 packets, got ${packets.length}`);
    for (const p of packets) {
        assert.ok(p.toBuffer().length <= 200);
        assert.equal(p.header.qr, 1);
        assert.equal(p.header.aa, 1);
        assert.equal(p.header.id, 0xCAFE);
        assert.equal(p.questions.length, 1);
        assert.equal(p.questions[0].type, PacketTypes.AXFR);
    }
    const first = packets[0];
    const last = packets[packets.length - 1];
    assert.equal(first.answers[0].packetType.type, PacketTypes.SOA);
    assert.equal(last.answers[last.answers.length - 1].packetType.type, PacketTypes.SOA);
    const allAnswers = packets.flatMap((p) => p.answers);
    const soaCount = allAnswers.filter((r) => r.packetType.type === PacketTypes.SOA).length;
    assert.equal(soaCount, 2);
    assert.equal(allAnswers.length, zone.records.length + 1);
});
test('zone#toAxfrPackets does not share header objects across frames', () => {
    const zone = Zone.fromZoneFile(SAMPLE_ZONE);
    const query = new Packet();
    query.header.id = 0x1234;
    query.questions.push(new PacketQuestion('example.com', PacketTypes.AXFR, PacketClass.IN));
    const packets = zone.toAxfrPackets(query, { maxMessageSize: 200 });
    assert.ok(packets.length >= 2);
    packets[0].header.rcode = 5;
    for (let i = 1; i < packets.length; i++) {
        assert.notEqual(packets[i].header, packets[0].header);
        assert.equal(packets[i].header.rcode, 0);
    }
});
test('zone#toAxfrPackets end-to-end through AxfrClient with forced splitting', async () => {
    const zone = Zone.fromZoneFile(SAMPLE_ZONE);
    const server = new DnsServer({
        tcp: true,
        handle: (request, send) => {
            send(zone.toAxfrPackets(request, { maxMessageSize: 200 }));
        },
    });
    const addresses = await server.listen();
    const port = addresses.tcp.port;
    const transfer = AxfrClient.request({ dns: '127.0.0.1', port: port });
    const result = await transfer('example.com');
    assert.equal(result.records.length, zone.records.length);
    assert.equal(result.soa.packetType.serial, 2024010101);
    const types = result.records.map((r) => r.packetType.type).sort();
    const expected = zone.records.map((r) => r.packetType.type).sort();
    assert.deepEqual(types, expected);
    await server.close();
});
test('zone#toAxfrPackets throws when one record cannot fit at all', () => {
    const zone = Zone.fromZoneFile(SAMPLE_ZONE);
    const query = new Packet();
    query.questions.push(new PacketQuestion('example.com', PacketTypes.AXFR, PacketClass.IN));
    assert.throws(() => zone.toAxfrPackets(query, { maxMessageSize: 50 }), /does not fit/u);
});
test('axfr#client errors on premature close', async () => {
    const server = new DnsServer({
        tcp: true,
        handle: (request, send) => {
            const zone = Zone.fromZoneFile(SAMPLE_ZONE);
            const partial = Packet.createResponseFromRequest(request);
            partial.questions = request.questions.slice();
            partial.answers = [zone.soa()];
            send(partial);
        },
    });
    const addresses = await server.listen();
    const port = addresses.tcp.port;
    const transfer = AxfrClient.request({ dns: '127.0.0.1', port: port });
    await assert.rejects(transfer('example.com'), /final SOA/);
    await server.close();
});
test('server/tcp#multi-packet send writes all frames', async () => {
    const server = new DnsServer({
        tcp: true,
        handle: (request, send) => {
            const a = new Packet();
            a.header.id = 1;
            a.header.qr = 1;
            a.questions = request.questions.slice();
            const b = new Packet();
            b.header.id = 2;
            b.header.qr = 1;
            b.questions = request.questions.slice();
            send([a, b]);
        },
    });
    const addresses = await server.listen();
    const port = addresses.tcp.port;
    const tcp = await import('net');
    const conn = tcp.connect({ port: port, host: '127.0.0.1' });
    await new Promise((resolve, reject) => {
        conn.once('connect', () => resolve());
        conn.once('error', reject);
    });
    const query = new Packet();
    query.header.id = 0x9999;
    query.questions.push(new PacketQuestion('multi.test', PacketTypes.A, PacketClass.IN));
    const buf = query.toBuffer();
    const len = Buffer.alloc(2);
    len.writeUInt16BE(buf.length);
    conn.write(Buffer.concat([len, buf]));
    const all = await new Promise((resolve, reject) => {
        const chunks = [];
        conn.on('data', (c) => chunks.push(c));
        conn.on('end', () => resolve(Buffer.concat(chunks)));
        conn.on('error', reject);
    });
    const len1 = all.readUInt16BE(0);
    const p1 = Packet.parse(all.subarray(2, 2 + len1));
    const len2 = all.readUInt16BE(2 + len1);
    const p2 = Packet.parse(all.subarray(4 + len1, 4 + len1 + len2));
    assert.equal(p1.header.id, 1);
    assert.equal(p2.header.id, 2);
    assert.equal(all.length, 4 + len1 + len2);
    await server.close();
});
//# sourceMappingURL=axfr.js.map