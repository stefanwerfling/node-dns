import assert from 'assert';
import {Buffer} from 'buffer';
import {BufferReader} from '../Lib/BufferReader.js';
import {BufferWriter} from '../Lib/BufferWriter.js';
import {test} from './test.js';

test('BufferWriter#aligned 8/16/32-bit writes match Buffer-native ones', () => {
    const w = new BufferWriter();
    w.write(0xAB, 8);
    w.write(0xCDEF, 16);
    w.write(0x12345678, 32);
    assert.deepEqual(w.toBuffer(), Buffer.from([0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78]));
});

test('BufferWriter#unaligned 1- and 4-bit writes share bytes', () => {
    // Mirror the DNS header flag layout: byte 2 = QR(1) | OPCODE(4) | AA(1) | TC(1) | RD(1)
    const w = new BufferWriter();
    w.write(1, 1);          // QR=1
    w.write(0xA, 4);        // OPCODE=10
    w.write(0, 1);          // AA=0
    w.write(1, 1);          // TC=1
    w.write(1, 1);          // RD=1
    // Expected byte: 1 1010 0 1 1 → 11010011b = 0xD3
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
    w.write(1, 1);                                  // 1 bit, now bit-unaligned
    w.writeBuffer(Buffer.from([0xFF, 0x01]));       // 16 more bits
    // Layout: 1 11111111 00000001 0000000 (padded to byte)
    //       = 11111111 10000000 10000000
    //       = 0xFF 0x80 0x80
    assert.deepEqual(w.toBuffer(), Buffer.from([0xFF, 0x80, 0x80]));
});

test('BufferWriter#writeBuffer of nested BufferWriter merges bits', () => {
    const inner = new BufferWriter();
    inner.write(0x1234, 16);
    inner.write(5, 3);             // 19 bits total; final byte has 3 high bits set

    const outer = new BufferWriter();
    outer.write(0xAB, 8);
    outer.writeBuffer(inner);
    outer.write(0, 5);             // pad to byte

    // outer should hold: 0xAB | 0x12 0x34 | bits 5(101) padded with 5 zeros
    // → 0xAB 0x12 0x34 (101_00000) = 0xA0
    assert.deepEqual(outer.toBuffer(), Buffer.from([0xAB, 0x12, 0x34, 0xA0]));
});

test('BufferWriter.getByteOffset stays in sync with name-compression callers', () => {
    const w = new BufferWriter();
    w.write(0x29, 16);
    assert.equal(w.getByteOffset(), 2);
    w.write(0x80, 8);
    assert.equal(w.getByteOffset(), 3);
    // Sub-byte write floors to the current byte until the byte completes.
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
    // Reverse direction of the writer test above.
    const r = new BufferReader(Buffer.from([0xD3]));
    assert.equal(r.read(1), 1);          // QR
    assert.equal(r.read(4), 0xA);        // OPCODE
    assert.equal(r.read(1), 0);          // AA
    assert.equal(r.read(1), 1);          // TC
    assert.equal(r.read(1), 1);          // RD
});

test('BufferReader#static read with arbitrary bit alignment', () => {
    const buf = Buffer.from([0b10110011, 0b01010101]);
    // Read 7 bits starting at bit 1 → 0b0110011 = 51
    assert.equal(BufferReader.read(buf, 1, 7), 0b0110011);
    // Read 12 bits starting at bit 2 → take 6 from byte0, 6 from byte1
    //   byte0 bits 2-7 = 110011, byte1 bits 0-5 = 010101 → 110011010101 = 0xCD5
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

    // Write a 12-bit prefix then the byte payload to exercise the
    // unaligned-then-aligned transition.
    w.write(0xABC, 12);
    w.writeBuffer(payload);

    const out = w.toBuffer();
    const r = new BufferReader(out);
    assert.equal(r.read(12), 0xABC);

    for (let i = 0; i < payload.length; i++) {
        assert.equal(r.read(8), payload[i]);
    }
});