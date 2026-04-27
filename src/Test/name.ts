import assert from 'assert';
import {BufferReader} from '../Lib/BufferReader.js';
import {BufferWriter} from '../Lib/BufferWriter.js';
import {PacketName} from '../Packet/PacketName.js';
import {response} from './helpers.js';
import {test} from './test.js';

test('Name#encode', () => {
    const name = PacketName.encode('www.google.com');
    const pattern = [3, 'w', 'w', 'w', 5, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', '0'];
    assert.equal(name.length, pattern.length);
});

test('Name#compression', () => {
    const writer = new BufferWriter();

    // Write first name: www.example.com (uncompressed)
    PacketName.encode('www.example.com', writer);
    const firstLen = writer.getByteOffset();
    // 3 + www + 7 + example + 3 + com + 0 = 1+3+1+7+1+3+1 = 17 bytes
    assert.equal(firstLen, 17);

    // Write second name: mail.example.com — "example.com" should be a pointer
    PacketName.encode('mail.example.com', writer);
    const secondLen = writer.getByteOffset() - firstLen;
    // 4 + mail + 2-byte pointer = 1+4+2 = 7 bytes (instead of 18 uncompressed)
    assert.equal(secondLen, 7);

    // Verify the encoded names can be decoded correctly
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