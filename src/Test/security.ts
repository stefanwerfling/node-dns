import assert from 'assert';
import {AddressInfo} from 'net';
import {UDPClient} from '../Client/UDPClient.js';
import {Bailiwick} from '../Lib/Bailiwick.js';
import {Random0x20} from '../Lib/Random0x20.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {EDNS, EdnsECS} from '../Packet/Types/EDNS.js';
import {DnsServer} from '../Server/DnsServer.js';
import {test} from './test.js';

// -- Random0x20 -----------------------------------------------------------

test('Random0x20#scramble preserves length and label structure', () => {
    const out = Random0x20.scramble('www.example.com');
    assert.equal(out.length, 'www.example.com'.length);
    // Dots stay where they were.
    assert.equal(out.indexOf('.'), 'www.example.com'.indexOf('.'));
    assert.equal(out.lastIndexOf('.'), 'www.example.com'.lastIndexOf('.'));
});

test('Random0x20#scramble only flips ASCII letters', () => {
    const input = 'host-3.example.com';
    const out = Random0x20.scramble(input);

    for (let i = 0; i < input.length; i++) {
        const c = input.charCodeAt(i);
        const isLetter = (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A);

        if (!isLetter) {
            assert.equal(out[i], input[i]);
        } else {
            // Same letter modulo case.
            assert.equal(out[i].toLowerCase(), input[i].toLowerCase());
        }
    }
});

test('Random0x20#scramble has visible randomness over many letters', () => {
    // With a 100-letter input, the chance of "all 100 bits land the same way"
    // is 2^-100; well below what any test should worry about.
    const input = 'a'.repeat(100);
    let upper = 0;
    let lower = 0;

    for (const ch of Random0x20.scramble(input)) {
        if (ch === 'A') upper++;
        if (ch === 'a') lower++;
    }

    assert.equal(upper + lower, 100);
    assert.ok(upper > 20 && lower > 20, `expected mixed case, got ${upper}U/${lower}L`);
});

test('Random0x20#matches is case-sensitive', () => {
    assert.equal(Random0x20.matches('ExaMple.COM', 'ExaMple.COM'), true);
    assert.equal(Random0x20.matches('ExaMple.COM', 'example.com'), false);
    assert.equal(Random0x20.matches('a.b', 'a.b'), true);
});

test('Random0x20#scramble + matches roundtrips trivially', () => {
    const scrambled = Random0x20.scramble('www.example.com');
    assert.equal(Random0x20.matches(scrambled, scrambled), true);
});

// -- Bailiwick ------------------------------------------------------------

test('Bailiwick#contains identity and subdomain', () => {
    assert.equal(Bailiwick.contains('example.com', 'example.com'), true);
    assert.equal(Bailiwick.contains('example.com', 'www.example.com'), true);
    assert.equal(Bailiwick.contains('example.com', 'a.b.c.example.com'), true);
});

test('Bailiwick#contains rejects sibling and parent', () => {
    assert.equal(Bailiwick.contains('example.com', 'other.com'), false);
    assert.equal(Bailiwick.contains('example.com', 'com'), false);
    assert.equal(Bailiwick.contains('example.com', 'fakeexample.com'), false);
});

test('Bailiwick#contains is case-insensitive and dot-tolerant', () => {
    assert.equal(Bailiwick.contains('Example.COM', 'www.example.com'), true);
    assert.equal(Bailiwick.contains('example.com.', 'www.example.com'), true);
    assert.equal(Bailiwick.contains('example.com', 'www.example.com.'), true);
});

test('Bailiwick#contains root zone matches everything', () => {
    assert.equal(Bailiwick.contains('.', 'example.com'), true);
    assert.equal(Bailiwick.contains('', 'example.com'), true);
});

test('Bailiwick#filter strips out-of-zone records', () => {
    const packet = new Packet();
    packet.questions.push(new PacketQuestion('example.com', PacketTypes.A, PacketClass.IN));
    packet.answers.push(new PacketResource('www.example.com', new A('192.0.2.1'), PacketClass.IN, 60));
    packet.answers.push(new PacketResource('evil.bank.com', new A('192.0.2.99'), PacketClass.IN, 60));
    packet.additionals.push(new PacketResource('mx.example.com', new A('192.0.2.2'), PacketClass.IN, 60));
    packet.additionals.push(new PacketResource('cdn.other.com', new A('192.0.2.3'), PacketClass.IN, 60));

    const filtered = Bailiwick.filter(packet, 'example.com');

    assert.equal(filtered.questions.length, 1);
    assert.equal(filtered.answers.length, 1);
    assert.equal(filtered.answers[0].name, 'www.example.com');
    assert.equal(filtered.additionals.length, 1);
    assert.equal(filtered.additionals[0].name, 'mx.example.com');
});

test('Bailiwick#filter keeps EDNS OPT records (empty owner name)', () => {
    const packet = new Packet();
    packet.questions.push(new PacketQuestion('example.com', PacketTypes.A, PacketClass.IN));
    packet.additionals.push(EDNS.createResource([new EdnsECS('192.0.2.0/24')]));

    const filtered = Bailiwick.filter(packet, 'example.com');
    assert.equal(filtered.additionals.length, 1);
});

// -- 0x20 client integration ----------------------------------------------

test('client/0x20#mismatch throws', async() => {
    // Server intentionally lower-cases the question name in its response —
    // simulates a buggy or hostile recursor.
    const server = new DnsServer({
        udp: true,
        handle: (request, send): void => {
            const response = Packet.createResponseFromRequest(request);
            response.questions = request.questions.map((q) => new PacketQuestion(
                q.name.toLowerCase(),
                q.type,
                q.class,
            ));
            response.answers.push(new PacketResource(
                request.questions[0].name, new A('192.0.2.1'), PacketClass.IN, 60,
            ));
            send(response);
        },
    });

    const addresses = await server.listen();
    const port = addresses.udp!.port;

    const resolve = UDPClient.request({
        dns: '127.0.0.1',
        port: port,
        use0x20: true,
        // The 14-letter name guarantees the scrambled form differs from
        // the all-lowercase form with overwhelming probability.
        tcpFallback: false,
    });

    await assert.rejects(
        resolve('LongTestName.example.com', PacketTypes.A, PacketClass.IN),
        /0x20 mismatch/,
    );

    await server.close();
});

test('client/0x20#preserves case when server echoes correctly', async() => {
    const server = new DnsServer({
        udp: true,
        handle: (request, send): void => {
            // Compliant server: echo the question verbatim.
            const response = Packet.createResponseFromRequest(request);
            response.questions = request.questions.slice();
            response.answers.push(new PacketResource(
                request.questions[0].name, new A('192.0.2.1'), PacketClass.IN, 60,
            ));
            send(response);
        },
    });

    const addresses = await server.listen();
    const port = addresses.udp!.port;

    const resolve = UDPClient.request({
        dns: '127.0.0.1',
        port: port,
        use0x20: true,
        tcpFallback: false,
    });

    const result = await resolve('LongTestName.example.com', PacketTypes.A, PacketClass.IN);
    assert.equal(result.answers.length, 1);
    assert.equal((result.answers[0].packetType as A).address, '192.0.2.1');

    await server.close();
});