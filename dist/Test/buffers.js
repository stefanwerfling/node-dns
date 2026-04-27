import assert from 'assert';
import { Buffer } from 'buffer';
import { BufferReader } from '../Lib/BufferReader.js';
import { BufferWriter } from '../Lib/BufferWriter.js';
import { test } from './test.js';
test('BufferWriter#aligned 8/16/32-bit writes match Buffer-native ones', () => {
    const w = new BufferWriter();
    w.write(0xAB, 8);
    w.write(0xCDEF, 16);
    w.write(0x12345678, 32);
    assert.deepEqual(w.toBuffer(), Buffer.from([0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78]));
});
test('BufferWriter#unaligned 1- and 4-bit writes share bytes', () => {
    const w = new BufferWriter();
    w.write(1, 1);
    w.write(0xA, 4);
    w.write(0, 1);
    w.write(1, 1);
    w.write(1, 1);
    assert.deepEqual(w.toBuffer(), Buffer.from([0xD3]));
});
test('BufferWriter#large writeBuffer stays byte-aligned', () => {
    const w = new BufferWriter();
    const big = Buffer.alloc(10_000, 0x42);
    w.writeBuffer(big);
    assert.equal(w.toBuffer().length, big.length);
    assert.equal(w.toBuffer()[5000], 0x42);
});
test('BufferWriter#writeBuffer after odd-bit write stays consistent', () => {
    const w = new BufferWriter();
    w.write(1, 1);
    w.writeBuffer(Buffer.from([0xFF, 0x01]));
    assert.deepEqual(w.toBuffer(), Buffer.from([0xFF, 0x80, 0x80]));
});
test('BufferWriter#writeBuffer of nested BufferWriter merges bits', () => {
    const inner = new BufferWriter();
    inner.write(0x1234, 16);
    inner.write(5, 3);
    const outer = new BufferWriter();
    outer.write(0xAB, 8);
    outer.writeBuffer(inner);
    outer.write(0, 5);
    assert.deepEqual(outer.toBuffer(), Buffer.from([0xAB, 0x12, 0x34, 0xA0]));
});
test('BufferWriter.getByteOffset stays in sync with name-compression callers', () => {
    const w = new BufferWriter();
    w.write(0x29, 16);
    assert.equal(w.getByteOffset(), 2);
    w.write(0x80, 8);
    assert.equal(w.getByteOffset(), 3);
    w.write(0xF, 4);
    assert.equal(w.getByteOffset(), 3);
    w.write(0xF, 4);
    assert.equal(w.getByteOffset(), 4);
});
test('BufferReader#aligned 8/16/32-bit reads match the original byte stream', () => {
    const buf = Buffer.from([0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78]);
    const r = new BufferReader(buf);
    assert.equal(r.read(8), 0xAB);
    assert.equal(r.read(16), 0xCDEF);
    assert.equal(r.read(32), 0x12345678);
});
test('BufferReader#unaligned bit reads recover header flags', () => {
    const r = new BufferReader(Buffer.from([0xD3]));
    assert.equal(r.read(1), 1);
    assert.equal(r.read(4), 0xA);
    assert.equal(r.read(1), 0);
    assert.equal(r.read(1), 1);
    assert.equal(r.read(1), 1);
});
test('BufferReader#static read with arbitrary bit alignment', () => {
    const buf = Buffer.from([0b10110011, 0b01010101]);
    assert.equal(BufferReader.read(buf, 1, 7), 0b0110011);
    assert.equal(BufferReader.read(buf, 2, 12), 0xCD5);
});
test('BufferReader.setOffset jumps and read continues correctly', () => {
    const buf = Buffer.from([0x00, 0x00, 0xAA, 0xBB]);
    const r = new BufferReader(buf);
    r.setOffset(8 * 2);
    assert.equal(r.read(16), 0xAABB);
    assert.equal(r.getOffset(), 8 * 4);
});
test('Reader/Writer roundtrip a 1 KiB random payload byte-perfectly', () => {
    const w = new BufferWriter();
    const payload = Buffer.alloc(1024);
    for (let i = 0; i < payload.length; i++) {
        payload[i] = (i * 37) & 0xFF;
    }
    w.write(0xABC, 12);
    w.writeBuffer(payload);
    const out = w.toBuffer();
    const r = new BufferReader(out);
    assert.equal(r.read(12), 0xABC);
    for (let i = 0; i < payload.length; i++) {
        assert.equal(r.read(8), payload[i]);
    }
});
//# sourceMappingURL=buffers.js.map