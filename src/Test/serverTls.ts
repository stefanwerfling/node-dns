import assert from 'assert';
import {AddressInfo} from 'net';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {A} from '../Packet/Types/A.js';
import {DnsServer} from '../Server/DnsServer.js';
import {TLSServer} from '../Server/TLSServer.js';
import {dotQuery, tlsCert, tlsKey} from './helpers.js';
import {test} from './test.js';

test('server/tls#requires-tls-options', () => {
    assert.throws(() => new TLSServer(null));
    assert.throws(() => new TLSServer({}));
    // tls block present but missing the inner `options` (cert/key) field
    assert.throws(() => new TLSServer({tls: {} as never}));
});

test('server/tls#standalone-roundtrip', async() => {
    const server = new TLSServer({
        tls: {options: {cert: tlsCert, key: tlsKey}}
    });

    server.on('request', (request, send) => {
        const response = Packet.createResponseFromRequest(request);
        response.answers.push(new PacketResource(
            request.questions[0].name, new A('5.5.5.5'), PacketClass.IN, 60
        ));
        send(response);
    });

    const address = await new Promise<AddressInfo>((resolve) => {
        server.on('listening', () => resolve(server.address() as AddressInfo));
        server.listen(0);
    });

    const result = await dotQuery(address.port, 'dot.test');
    assert.equal(result.header.id, 0xBEEF);
    assert.equal(result.answers.length, 1);
    assert.equal((result.answers[0].packetType as A).address, '5.5.5.5');

    server.close();
});

test('server/tls#dns-server-integration', async() => {
    const server = new DnsServer({
        tcp: true,
        tls: {options: {cert: tlsCert, key: tlsKey}},
        handle: (request, send): void => {
            const response = Packet.createResponseFromRequest(request);
            response.answers.push(new PacketResource(
                request.questions[0].name, new A('7.7.7.7'), PacketClass.IN, 60
            ));
            send(response);
        }
    });

    const addresses = await server.listen();
    assert.ok(addresses.tcp && (addresses.tcp as AddressInfo).port > 0);
    assert.ok(addresses.tls && (addresses.tls as AddressInfo).port > 0);
    assert.notEqual((addresses.tcp as AddressInfo).port, (addresses.tls as AddressInfo).port);

    const result = await dotQuery((addresses.tls as AddressInfo).port, 'dns-server.test');
    assert.equal((result.answers[0].packetType as A).address, '7.7.7.7');

    await server.close();
});