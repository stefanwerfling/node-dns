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