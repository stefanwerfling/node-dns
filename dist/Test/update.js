import assert from 'assert';
import dgram from 'dgram';
import { UpdateClient } from '../Client/UpdateClient.js';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketOpcode } from '../Packet/PacketOpcode.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { Tsig } from '../Packet/Tsig.js';
import { TsigAlgorithm, TsigKey } from '../Packet/TsigKey.js';
import { Update, UpdateBuilder, UpdateRcode } from '../Packet/Update.js';
import { A } from '../Packet/Types/A.js';
import { AAAA } from '../Packet/Types/AAAA.js';
import { TSIG, TsigError } from '../Packet/Types/TSIG.js';
import { Zone } from '../Packet/Zone.js';
import { DnsServer } from '../Server/DnsServer.js';
import { test } from './test.js';
const ZONE = `$ORIGIN example.com.
$TTL 3600
@   IN SOA ns1 admin (1 7200 3600 1209600 3600)
@   IN NS  ns1
www IN A   192.0.2.1
mail IN A  192.0.2.2
`;
test('update#builder produces opcode=UPDATE with right sections', () => {
    const builder = new UpdateBuilder('example.com')
        .requireNameInUse('www.example.com')
        .add(new PacketResource('mx.example.com', new A('192.0.2.10'), PacketClass.IN, 60));
    const packet = builder.toPacket();
    assert.equal(packet.header.opcode, PacketOpcode.UPDATE);
    assert.equal(packet.questions.length, 1);
    assert.equal(packet.questions[0].name, 'example.com');
    assert.equal(packet.questions[0].type, PacketTypes.SOA);
    assert.equal(packet.answers.length, 1);
    assert.equal(packet.authorities.length, 1);
});
test('update#wire-format roundtrip preserves rdlength=0 markers', () => {
    const builder = new UpdateBuilder('example.com')
        .requireNameInUse('www.example.com')
        .requireRRsetExists('mail.example.com', PacketTypes.A)
        .requireRRsetAbsent('nx.example.com', PacketTypes.AAAA)
        .deleteName('old.example.com')
        .deleteRRset('mail.example.com', PacketTypes.A);
    const parsed = Packet.parse(builder.toBuffer());
    const msg = Update.parse(parsed);
    assert.equal(msg.prerequisites.length, 3);
    assert.equal(msg.updates.length, 2);
    for (const r of [...msg.prerequisites, ...msg.updates]) {
        assert.equal(r.rdlength, 0);
    }
});
test('update#classifyPrerequisite — all five RFC 2136 §2.4 forms', () => {
    const builder = new UpdateBuilder('example.com')
        .requireNameInUse('www.example.com')
        .requireNameNotInUse('nx.example.com')
        .requireRRsetExists('mail.example.com', PacketTypes.A)
        .requireRRsetAbsent('nx.example.com', PacketTypes.AAAA)
        .requireRRsetMatches(new PacketResource('www.example.com', new A('192.0.2.1'), PacketClass.IN, 0));
    const msg = Update.parse(Packet.parse(builder.toBuffer()));
    const kinds = msg.prerequisites.map((r) => Update.classifyPrerequisite(r).kind);
    assert.deepEqual(kinds, ['nameInUse', 'nameNotInUse', 'rrsetExists', 'rrsetAbsent', 'rrsetMatchesExactly']);
});
test('update#classifyUpdate — all four RFC 2136 §2.5 forms', () => {
    const builder = new UpdateBuilder('example.com')
        .add(new PacketResource('mx.example.com', new A('192.0.2.10'), PacketClass.IN, 60))
        .deleteName('old.example.com')
        .deleteRRset('mail.example.com', PacketTypes.A)
        .deleteRR(new PacketResource('mail.example.com', new A('192.0.2.2'), PacketClass.IN, 0));
    const msg = Update.parse(Packet.parse(builder.toBuffer()));
    const kinds = msg.updates.map((r) => Update.classifyUpdate(r).kind);
    assert.deepEqual(kinds, ['add', 'deleteName', 'deleteRRset', 'deleteRR']);
});
test('update#applyToZone adds a record', () => {
    const zone = Zone.fromZoneFile(ZONE);
    const before = zone.records.length;
    const builder = new UpdateBuilder('example.com')
        .add(new PacketResource('mx.example.com', new A('192.0.2.10'), PacketClass.IN, 60));
    const rcode = Update.applyToZone(zone, Update.parse(Packet.parse(builder.toBuffer())));
    assert.equal(rcode, UpdateRcode.NOERROR);
    assert.equal(zone.records.length, before + 1);
    const added = zone.records[zone.records.length - 1];
    assert.equal(added.name, 'mx.example.com');
    assert.equal(added.packetType.address, '192.0.2.10');
});
test('update#applyToZone refreshes TTL on existing matching RR', () => {
    const zone = Zone.fromZoneFile(ZONE);
    const wwwBefore = zone.records.find((r) => r.name === 'www.example.com');
    assert.equal(wwwBefore.ttl, 3600);
    const builder = new UpdateBuilder('example.com')
        .add(new PacketResource('www.example.com', new A('192.0.2.1'), PacketClass.IN, 60));
    Update.applyToZone(zone, Update.parse(Packet.parse(builder.toBuffer())));
    const wwwAfter = zone.records.find((r) => r.name === 'www.example.com');
    assert.equal(wwwAfter.ttl, 60);
    assert.equal(zone.records.filter((r) => r.name === 'www.example.com').length, 1);
});
test('update#applyToZone deletes by name', () => {
    const zone = Zone.fromZoneFile(ZONE);
    const builder = new UpdateBuilder('example.com')
        .deleteName('www.example.com');
    Update.applyToZone(zone, Update.parse(Packet.parse(builder.toBuffer())));
    assert.equal(zone.records.find((r) => r.name === 'www.example.com'), undefined);
});
test('update#applyToZone deletes by RRset', () => {
    const zone = Zone.fromZoneFile(ZONE);
    zone.records.push(new PacketResource('www.example.com', new AAAA('2001:db8::1'), PacketClass.IN, 3600));
    const builder = new UpdateBuilder('example.com')
        .deleteRRset('www.example.com', PacketTypes.A);
    Update.applyToZone(zone, Update.parse(Packet.parse(builder.toBuffer())));
    const wwwRecords = zone.records.filter((r) => r.name === 'www.example.com');
    assert.equal(wwwRecords.length, 1);
    assert.equal(wwwRecords[0].packetType.type, PacketTypes.AAAA);
});
test('update#applyToZone deletes a specific RR', () => {
    const zone = Zone.fromZoneFile(ZONE);
    zone.records.push(new PacketResource('www.example.com', new A('192.0.2.99'), PacketClass.IN, 3600));
    const builder = new UpdateBuilder('example.com')
        .deleteRR(new PacketResource('www.example.com', new A('192.0.2.1'), PacketClass.IN, 0));
    Update.applyToZone(zone, Update.parse(Packet.parse(builder.toBuffer())));
    const wwwAddrs = zone.records
        .filter((r) => r.name === 'www.example.com' && r.packetType.type === PacketTypes.A)
        .map((r) => r.packetType.address);
    assert.deepEqual(wwwAddrs, ['192.0.2.99']);
});
test('update#applyToZone returns NXDOMAIN when nameInUse fails', () => {
    const zone = Zone.fromZoneFile(ZONE);
    const builder = new UpdateBuilder('example.com')
        .requireNameInUse('absent.example.com')
        .add(new PacketResource('absent.example.com', new A('1.2.3.4'), PacketClass.IN, 60));
    const rcode = Update.applyToZone(zone, Update.parse(Packet.parse(builder.toBuffer())));
    assert.equal(rcode, UpdateRcode.NXDOMAIN);
    assert.equal(zone.records.find((r) => r.name === 'absent.example.com'), undefined);
});
test('update#applyToZone returns YXDOMAIN when nameNotInUse fails', () => {
    const zone = Zone.fromZoneFile(ZONE);
    const builder = new UpdateBuilder('example.com')
        .requireNameNotInUse('www.example.com')
        .add(new PacketResource('www.example.com', new A('1.2.3.4'), PacketClass.IN, 60));
    const rcode = Update.applyToZone(zone, Update.parse(Packet.parse(builder.toBuffer())));
    assert.equal(rcode, UpdateRcode.YXDOMAIN);
});
test('update#applyToZone returns NXRRSET when rrsetExists fails', () => {
    const zone = Zone.fromZoneFile(ZONE);
    const builder = new UpdateBuilder('example.com')
        .requireRRsetExists('www.example.com', PacketTypes.AAAA)
        .add(new PacketResource('www.example.com', new AAAA('::1'), PacketClass.IN, 60));
    const rcode = Update.applyToZone(zone, Update.parse(Packet.parse(builder.toBuffer())));
    assert.equal(rcode, UpdateRcode.NXRRSET);
});
test('update#applyToZone returns YXRRSET when rrsetAbsent fails', () => {
    const zone = Zone.fromZoneFile(ZONE);
    const builder = new UpdateBuilder('example.com')
        .requireRRsetAbsent('www.example.com', PacketTypes.A)
        .deleteName('www.example.com');
    const rcode = Update.applyToZone(zone, Update.parse(Packet.parse(builder.toBuffer())));
    assert.equal(rcode, UpdateRcode.YXRRSET);
});
test('update#applyToZone returns NOTZONE when zone name does not match', () => {
    const zone = Zone.fromZoneFile(ZONE);
    const builder = new UpdateBuilder('other.zone')
        .add(new PacketResource('www.other.zone', new A('1.2.3.4'), PacketClass.IN, 60));
    const rcode = Update.applyToZone(zone, Update.parse(Packet.parse(builder.toBuffer())));
    assert.equal(rcode, UpdateRcode.NOTZONE);
});
test('update#end-to-end UDP via DnsServer + UpdateClient', async () => {
    const zone = Zone.fromZoneFile(ZONE);
    const server = new DnsServer({
        udp: true,
        handle: (request, send) => {
            if (request.header.opcode !== PacketOpcode.UPDATE) {
                send(Packet.createResponseFromRequest(request));
                return;
            }
            const rcode = Update.applyToZone(zone, Update.parse(request));
            send(Update.buildResponse(request, rcode));
        },
    });
    const addresses = await server.listen();
    const port = addresses.udp.port;
    const send = UpdateClient.request({ dns: '127.0.0.1', port: port });
    const ok = await send(new UpdateBuilder('example.com')
        .add(new PacketResource('new.example.com', new A('192.0.2.50'), PacketClass.IN, 300)));
    assert.equal(ok.header.opcode, PacketOpcode.UPDATE);
    assert.equal(ok.header.rcode, UpdateRcode.NOERROR);
    assert.ok(zone.records.some((r) => r.name === 'new.example.com'));
    const fail = await send(new UpdateBuilder('example.com')
        .requireNameNotInUse('www.example.com')
        .add(new PacketResource('extra.example.com', new A('1.1.1.1'), PacketClass.IN, 60)));
    assert.equal(fail.header.rcode, UpdateRcode.YXDOMAIN);
    assert.ok(!zone.records.some((r) => r.name === 'extra.example.com'));
    await server.close();
});
const sendRawUdp = (port, payload) => {
    return new Promise((resolve, reject) => {
        const socket = dgram.createSocket('udp4');
        socket.once('message', (msg) => {
            socket.close();
            resolve(msg);
        });
        socket.once('error', (err) => {
            socket.close();
            reject(err);
        });
        socket.send(payload, port, '127.0.0.1', (err) => {
            if (err) {
                socket.close();
                reject(err);
            }
        });
    });
};
test('update#TSIG-signed UPDATE end-to-end (server verifies + signs reply)', async () => {
    const zone = Zone.fromZoneFile(ZONE);
    const key = new TsigKey('update-key.', TsigAlgorithm.HMAC_SHA256, Buffer.from('shared-secret'));
    const fudgeNow = 1_700_000_000;
    const server = new DnsServer({
        udp: true,
        handle: (request, send, _client, raw) => {
            const verified = Tsig.verify(request, raw, key, { now: fudgeNow });
            const reply = Update.buildResponse(request, verified.valid
                ? Update.applyToZone(zone, Update.parse(request))
                : UpdateRcode.NOTAUTH);
            const signed = verified.valid
                ? Tsig.sign(reply, key, { timeSigned: fudgeNow, requestMac: verified.tsig.mac })
                : Tsig.sign(reply, key, { timeSigned: fudgeNow, error: TsigError.BADSIG });
            send(signed.buffer);
        },
    });
    const addresses = await server.listen();
    const port = addresses.udp.port;
    const requestPacket = new UpdateBuilder('example.com')
        .add(new PacketResource('signed.example.com', new A('192.0.2.77'), PacketClass.IN, 300))
        .toPacket();
    requestPacket.header.id = 0xABCD;
    const signedRequest = Tsig.sign(requestPacket, key, { timeSigned: fudgeNow });
    const responseRaw = await sendRawUdp(port, signedRequest.buffer);
    const responsePacket = Packet.parse(responseRaw);
    assert.equal(responsePacket.header.opcode, PacketOpcode.UPDATE);
    assert.equal(responsePacket.header.rcode, UpdateRcode.NOERROR);
    assert.ok(zone.records.some((r) => r.name === 'signed.example.com'));
    const verifiedResp = Tsig.verify(responsePacket, responseRaw, key, {
        requestMac: signedRequest.mac,
        now: fudgeNow
    });
    assert.equal(verifiedResp.valid, true, verifiedResp.reason);
    await server.close();
});
test('update#TSIG-signed UPDATE rejects wrong-secret with BADSIG', async () => {
    const zone = Zone.fromZoneFile(ZONE);
    const serverKey = new TsigKey('update-key.', TsigAlgorithm.HMAC_SHA256, Buffer.from('correct-secret'));
    const clientKey = new TsigKey('update-key.', TsigAlgorithm.HMAC_SHA256, Buffer.from('wrong-secret'));
    const fudgeNow = 1_700_000_000;
    const server = new DnsServer({
        udp: true,
        handle: (request, send, _client, raw) => {
            const verified = Tsig.verify(request, raw, serverKey, { now: fudgeNow });
            if (verified.valid) {
                const reply = Update.buildResponse(request, Update.applyToZone(zone, Update.parse(request)));
                send(Tsig.sign(reply, serverKey, {
                    timeSigned: fudgeNow,
                    requestMac: verified.tsig.mac
                }).buffer);
                return;
            }
            const reply = Update.buildResponse(request, UpdateRcode.NOTAUTH);
            send(Tsig.sign(reply, serverKey, {
                timeSigned: fudgeNow,
                error: TsigError.BADSIG
            }).buffer);
        },
    });
    const addresses = await server.listen();
    const port = addresses.udp.port;
    const requestPacket = new UpdateBuilder('example.com')
        .add(new PacketResource('rejected.example.com', new A('192.0.2.99'), PacketClass.IN, 300))
        .toPacket();
    requestPacket.header.id = 0xDEAD;
    const signedRequest = Tsig.sign(requestPacket, clientKey, { timeSigned: fudgeNow });
    const send = UpdateClient.request({ dns: '127.0.0.1', port: port });
    const responsePacket = await send(signedRequest.buffer);
    assert.equal(responsePacket.header.rcode, UpdateRcode.NOTAUTH);
    assert.ok(!zone.records.some((r) => r.name === 'rejected.example.com'));
    const lastAdd = responsePacket.additionals[responsePacket.additionals.length - 1];
    assert.ok(lastAdd && lastAdd.packetType instanceof TSIG);
    assert.equal(lastAdd.packetType.error, TsigError.BADSIG);
    await server.close();
});
//# sourceMappingURL=update.js.map