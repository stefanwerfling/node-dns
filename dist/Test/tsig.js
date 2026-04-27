import assert from 'assert';
import { Packet } from '../Packet/Packet.js';
import { PacketClass } from '../Packet/PacketClass.js';
import { PacketQuestion } from '../Packet/PacketQuestion.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { Tsig } from '../Packet/Tsig.js';
import { TsigAlgorithm, TsigKey } from '../Packet/TsigKey.js';
import { TSIG } from '../Packet/Types/TSIG.js';
import { test } from './test.js';
test('TSIG#record encode/decode roundtrip', () => {
    const mac = Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex');
    const packet = new Packet();
    packet.header.qr = 1;
    packet.additionals.push(new PacketResource('k.example.', new TSIG('hmac-sha256.', 1700000000, 300, mac, 0x1234, 0, Buffer.alloc(0)), PacketClass.ANY, 0));
    const parsed = Packet.parse(packet.toBuffer());
    const tsig = parsed.additionals[0].packetType;
    assert.equal(tsig.algorithm, 'hmac-sha256.');
    assert.equal(tsig.timeSigned, 1700000000);
    assert.equal(tsig.fudge, 300);
    assert.deepEqual(tsig.mac, mac);
    assert.equal(tsig.originalId, 0x1234);
});
test('TSIG#sign + verify roundtrip (sha256)', () => {
    const key = new TsigKey('shared.', TsigAlgorithm.HMAC_SHA256, Buffer.from('some-secret-bytes'));
    const query = new Packet();
    query.header.id = 0xCAFE;
    query.header.rd = 1;
    query.questions.push(new PacketQuestion('example.com', PacketTypes.A, PacketClass.IN));
    const signed = Tsig.sign(query, key, { timeSigned: 1700000000 });
    assert.ok(signed.buffer.length > 0);
    assert.equal(signed.mac.length, 32);
    const parsed = Packet.parse(signed.buffer);
    const result = Tsig.verify(parsed, signed.buffer, key, { skipTimeCheck: true });
    assert.equal(result.valid, true);
    assert.ok(result.tsig);
    assert.equal(result.tsig.originalId, 0xCAFE);
});
test('TSIG#sign + verify roundtrip (sha1)', () => {
    const key = new TsigKey('k.', TsigAlgorithm.HMAC_SHA1, Buffer.from('sha1-secret'));
    const q = new Packet();
    q.header.id = 1;
    q.questions.push(new PacketQuestion('a.example.', PacketTypes.TXT, PacketClass.IN));
    const signed = Tsig.sign(q, key, { timeSigned: 1700000000 });
    assert.equal(signed.mac.length, 20);
    const parsed = Packet.parse(signed.buffer);
    const result = Tsig.verify(parsed, signed.buffer, key, { skipTimeCheck: true });
    assert.equal(result.valid, true);
});
test('TSIG#verify rejects wrong secret', () => {
    const keyA = new TsigKey('k.', TsigAlgorithm.HMAC_SHA256, Buffer.from('secret-A'));
    const keyB = new TsigKey('k.', TsigAlgorithm.HMAC_SHA256, Buffer.from('secret-B'));
    const q = new Packet();
    q.header.id = 2;
    q.questions.push(new PacketQuestion('a.example.', PacketTypes.A, PacketClass.IN));
    const signed = Tsig.sign(q, keyA, { timeSigned: 1700000000 });
    const parsed = Packet.parse(signed.buffer);
    const result = Tsig.verify(parsed, signed.buffer, keyB, { skipTimeCheck: true });
    assert.equal(result.valid, false);
    assert.ok(result.reason?.includes('MAC verification failed'));
});
test('TSIG#verify rejects wrong key name', () => {
    const keyA = new TsigKey('a.', TsigAlgorithm.HMAC_SHA256, Buffer.from('s'));
    const keyB = new TsigKey('b.', TsigAlgorithm.HMAC_SHA256, Buffer.from('s'));
    const q = new Packet();
    q.questions.push(new PacketQuestion('a.example.', PacketTypes.A, PacketClass.IN));
    const signed = Tsig.sign(q, keyA, { timeSigned: 1700000000 });
    const parsed = Packet.parse(signed.buffer);
    const result = Tsig.verify(parsed, signed.buffer, keyB, { skipTimeCheck: true });
    assert.equal(result.valid, false);
    assert.ok(result.reason?.includes('key name mismatch'));
});
test('TSIG#verify rejects tampered message', () => {
    const key = new TsigKey('k.', TsigAlgorithm.HMAC_SHA256, Buffer.from('s'));
    const q = new Packet();
    q.header.id = 7;
    q.questions.push(new PacketQuestion('a.example.', PacketTypes.A, PacketClass.IN));
    const signed = Tsig.sign(q, key, { timeSigned: 1700000000 });
    const tampered = Buffer.from(signed.buffer);
    tampered[20] = (tampered[20] + 1) % 256;
    const parsed = Packet.parse(tampered);
    const result = Tsig.verify(parsed, tampered, key, { skipTimeCheck: true });
    assert.equal(result.valid, false);
});
test('TSIG#response MAC chains from request MAC', () => {
    const key = new TsigKey('k.', TsigAlgorithm.HMAC_SHA256, Buffer.from('s'));
    const request = new Packet();
    request.header.id = 42;
    request.questions.push(new PacketQuestion('a.example.', PacketTypes.A, PacketClass.IN));
    const signedRequest = Tsig.sign(request, key, { timeSigned: 1700000000 });
    const parsedReq = Packet.parse(signedRequest.buffer);
    const reqCheck = Tsig.verify(parsedReq, signedRequest.buffer, key, { skipTimeCheck: true });
    assert.equal(reqCheck.valid, true);
    const reply = Packet.createResponseFromRequest(parsedReq);
    reply.header.qr = 1;
    const signedResponse = Tsig.sign(reply, key, {
        timeSigned: 1700000000,
        requestMac: signedRequest.mac
    });
    const parsedResp = Packet.parse(signedResponse.buffer);
    const respCheck = Tsig.verify(parsedResp, signedResponse.buffer, key, {
        requestMac: signedRequest.mac,
        skipTimeCheck: true
    });
    assert.equal(respCheck.valid, true);
    const badCheck = Tsig.verify(parsedResp, signedResponse.buffer, key, { skipTimeCheck: true });
    assert.equal(badCheck.valid, false);
});
test('TSIG#verify enforces fudge window', () => {
    const key = new TsigKey('k.', TsigAlgorithm.HMAC_SHA256, Buffer.from('s'));
    const q = new Packet();
    q.questions.push(new PacketQuestion('a.example.', PacketTypes.A, PacketClass.IN));
    const signed = Tsig.sign(q, key, { timeSigned: 1_000_000, fudge: 300 });
    const parsed = Packet.parse(signed.buffer);
    const inWindow = Tsig.verify(parsed, signed.buffer, key, { now: 1_000_100 });
    assert.equal(inWindow.valid, true);
    const outOfWindow = Tsig.verify(parsed, signed.buffer, key, { now: 1_001_000 });
    assert.equal(outOfWindow.valid, false);
    assert.ok(outOfWindow.reason?.includes('fudge'));
});
//# sourceMappingURL=tsig.js.map