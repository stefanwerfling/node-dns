import assert from 'assert';
import { NotifyClient } from '../Client/NotifyClient.js';
import { ClientOptionsProtocol } from '../Client/ClientOptions.js';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketOpcode } from '../Packet/PacketOpcode.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { SOA } from '../Packet/Types/SOA.js';
import { DnsServer } from '../Server/DnsServer.js';
import { test } from './test.js';
test('notify#makeQuery sets opcode, AA, question (RFC 1996 §3.7)', () => {
    const query = NotifyClient.makeQuery('example.com');
    assert.equal(query.header.opcode, PacketOpcode.NOTIFY);
    assert.equal(query.header.aa, 1);
    assert.equal(query.header.rd, 0);
    assert.equal(query.questions.length, 1);
    assert.equal(query.questions[0].name, 'example.com');
    assert.equal(query.questions[0].type, PacketTypes.SOA);
    assert.equal(query.questions[0].class, PacketClass.IN);
    assert.equal(query.answers.length, 0);
});
test('notify#makeQuery includes optional source SOA in answer section', () => {
    const soa = new SOA('ns1.example.com', 'admin.example.com', 2024010101, 7200, 3600, 1209600, 3600);
    const query = NotifyClient.makeQuery('example.com', soa);
    assert.equal(query.answers.length, 1);
    assert.equal(query.answers[0].name, 'example.com');
    assert.equal(query.answers[0].packetType.serial, 2024010101);
});
test('notify#wire-format roundtrip preserves opcode', () => {
    const query = NotifyClient.makeQuery('example.com');
    const parsed = Packet.parse(query.toBuffer());
    assert.equal(parsed.header.opcode, PacketOpcode.NOTIFY);
    assert.equal(parsed.header.aa, 1);
    assert.equal(parsed.questions[0].name, 'example.com');
    assert.equal(parsed.questions[0].type, PacketTypes.SOA);
});
test('notify#end-to-end UDP: secondary receives and acknowledges', async () => {
    let received = null;
    const server = new DnsServer({
        udp: true,
        handle: (request, send) => {
            received = request;
            const response = Packet.createResponseFromRequest(request);
            response.questions = request.questions.slice();
            response.header.opcode = PacketOpcode.NOTIFY;
            response.header.aa = 1;
            response.header.rcode = 0;
            send(response);
        },
    });
    const addresses = await server.listen();
    const port = addresses.udp.port;
    const notify = NotifyClient.request({ dns: '127.0.0.1', port: port });
    const response = await notify('example.com');
    assert.equal(received.header.opcode, PacketOpcode.NOTIFY);
    assert.equal(received.questions[0].name, 'example.com');
    assert.equal(response.header.qr, 1);
    assert.equal(response.header.opcode, PacketOpcode.NOTIFY);
    assert.equal(response.header.rcode, 0);
    await server.close();
});
test('notify#end-to-end TCP', async () => {
    const server = new DnsServer({
        tcp: true,
        handle: (request, send) => {
            const response = Packet.createResponseFromRequest(request);
            response.questions = request.questions.slice();
            response.header.opcode = PacketOpcode.NOTIFY;
            response.header.aa = 1;
            response.header.rcode = 0;
            send(response);
        },
    });
    const addresses = await server.listen();
    const port = addresses.tcp.port;
    const notify = NotifyClient.request({
        dns: '127.0.0.1',
        port: port,
        protocol: ClientOptionsProtocol.tcp,
    });
    const response = await notify('example.com');
    assert.equal(response.header.opcode, PacketOpcode.NOTIFY);
    assert.equal(response.header.rcode, 0);
    await server.close();
});
test('notify#secondary refuses unknown zone with NOTAUTH', async () => {
    const server = new DnsServer({
        udp: true,
        handle: (request, send) => {
            const response = Packet.createResponseFromRequest(request);
            response.questions = request.questions.slice();
            response.header.opcode = PacketOpcode.NOTIFY;
            response.header.rcode = 9;
            send(response);
        },
    });
    const addresses = await server.listen();
    const port = addresses.udp.port;
    const notify = NotifyClient.request({ dns: '127.0.0.1', port: port });
    const response = await notify('not.our.zone');
    assert.equal(response.header.rcode, 9);
    await server.close();
});
//# sourceMappingURL=notify.js.map