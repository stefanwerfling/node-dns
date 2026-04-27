import assert from 'assert';
import { BufferReader } from '../Lib/BufferReader.js';
import { BufferWriter } from '../Lib/BufferWriter.js';
import { PacketName } from '../Packet/PacketName.js';
import { response } from './helpers.js';
import { test } from './test.js';
test('Name#encode', () => {
    const name = PacketName.encode('www.google.com');
    const pattern = [3, 'w', 'w', 'w', 5, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', '0'];
    assert.equal(name.length, pattern.length);
});
test('Name#compression', () => {
    const writer = new BufferWriter();
    PacketName.encode('www.example.com', writer);
    const firstLen = writer.getByteOffset();
    assert.equal(firstLen, 17);
    PacketName.encode('mail.example.com', writer);
    const secondLen = writer.getByteOffset() - firstLen;
    assert.equal(secondLen, 7);
    const buf = writer.toBuffer();
    const reader = new BufferReader(buf);
    assert.equal(PacketName.decode(reader), 'www.example.com');
    assert.equal(PacketName.decode(reader), 'mail.example.com');
});
test('Name#decode', () => {
    const reader = new BufferReader(response, 8 * 12);
    let name = PacketName.decode(reader);
    assert.equal(name, 'www.z.cn');
    reader.setOffset(8 * 26);
    name = PacketName.decode(reader);
    assert.equal(reader.getOffset(), 8 * 28);
    assert.equal(name, 'www.z.cn');
});
//# sourceMappingURL=name.js.map