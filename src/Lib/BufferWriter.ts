import { Buffer } from 'buffer';

/**
 * Bit-precise writer that backs onto a byte array.
 *
 * The original implementation stored each bit as its own `number[]` element
 * and flipped bits into bytes only at `toBuffer()`. That made every 32-bit
 * `write()` allocate 32 array slots and every byte append loop `Array#push`
 * eight times — fine for tests, expensive at zone-transfer scale.
 *
 * The new representation is a `number[]` of byte values plus a `_bitLength`
 * counter. Aligned writes (8/16/32 bits at a byte boundary — i.e. almost
 * everything in DNS once you're past the 12-byte header) take a hot path
 * that drops the bytes straight in. Sub-byte writes (the 1- and 4-bit
 * fields in the header) take a slower bit-shift loop but stay in
 * Number-arithmetic — no per-bit allocations.
 *
 * `getByteOffset()` keeps its semantics for name-compression callers; it
 * floors the bit length to a byte so `setNameOffset` always sees the
 * byte-aligned position where the next label's length byte will land.
 */
export class BufferWriter {

    /**
     * Backing byte storage. Each entry is in [0, 255]. Grown by `push` /
     * direct index assignment as `write` is called.
     * @protected
     */
    protected _bytes: number[] = [];

    /**
     * Bits written so far. `_bytes.length === Math.ceil(_bitLength / 8)`.
     * @protected
     */
    protected _bitLength: number = 0;

    /**
     * Tracks byte offsets of previously written domain name suffixes
     * for DNS name compression (RFC 1035 Section 4.1.4).
     * @protected
     */
    protected _nameOffsets: Map<string, number> = new Map();

    /**
     * Append `size` bits of `d` to the buffer. The most-significant bit of
     * `d` (within `size`) lands first — same convention as the previous
     * bit-array implementation.
     */
    public write(d: number, size: number): void {
        // eslint-disable-next-line no-bitwise
        const bitInByte = this._bitLength & 7;

        // Hot path: byte-aligned 8/16/32-bit writes via direct array stores.
        if (bitInByte === 0) {
            if (size === 8) {
                // eslint-disable-next-line no-bitwise
                this._bytes.push(d & 0xFF);
                this._bitLength += 8;
                return;
            }

            if (size === 16) {
                // eslint-disable-next-line no-bitwise
                this._bytes.push((d >>> 8) & 0xFF, d & 0xFF);
                this._bitLength += 16;
                return;
            }

            if (size === 32) {
                this._bytes.push(
                    // eslint-disable-next-line no-bitwise
                    (d >>> 24) & 0xFF,
                    // eslint-disable-next-line no-bitwise
                    (d >>> 16) & 0xFF,
                    // eslint-disable-next-line no-bitwise
                    (d >>> 8) & 0xFF,
                    // eslint-disable-next-line no-bitwise
                    d & 0xFF,
                );
                this._bitLength += 32;
                return;
            }
        }

        // Cold path: arbitrary bit width and/or unaligned offset.
        let bitsLeft = size;

        while (bitsLeft > 0) {
            // eslint-disable-next-line no-bitwise
            const byteOffset = this._bitLength >> 3;
            // eslint-disable-next-line no-bitwise
            const curBitInByte = this._bitLength & 7;
            const room = 8 - curBitInByte;
            const take = room < bitsLeft ? room : bitsLeft;
            const shiftSrc = bitsLeft - take;
            const shiftDst = room - take;
            // eslint-disable-next-line no-bitwise
            const bits = (d >>> shiftSrc) & ((1 << take) - 1);

            if (this._bytes.length <= byteOffset) {
                this._bytes.push(0);
            }

            // eslint-disable-next-line no-bitwise
            this._bytes[byteOffset] |= bits << shiftDst;

            bitsLeft -= take;
            this._bitLength += take;
        }
    }

    /**
     * Append a byte buffer or another writer's content. The byte-aligned
     * fast path does a plain `push` per byte; an unaligned writer falls
     * back to the bit-shift loop.
     */
    public writeBuffer(buffer: Buffer|BufferWriter): void {
        // eslint-disable-next-line no-bitwise
        const aligned = (this._bitLength & 7) === 0;

        if (buffer instanceof BufferWriter) {
            const otherBytes = buffer._bytes;
            const otherBitLength = buffer._bitLength;
            // eslint-disable-next-line no-bitwise
            const otherFullBytes = otherBitLength >> 3;
            const otherRemainderBits = otherBitLength - otherFullBytes * 8;

            if (aligned) {
                for (let i = 0; i < otherFullBytes; i++) {
                    this._bytes.push(otherBytes[i]);
                }

                this._bitLength += otherFullBytes * 8;
            } else {
                for (let i = 0; i < otherFullBytes; i++) {
                    this.write(otherBytes[i], 8);
                }
            }

            if (otherRemainderBits > 0) {
                // High `otherRemainderBits` bits of the last byte hold the
                // tail; left-justify them when appending so the bit shape
                // is preserved.
                // eslint-disable-next-line no-bitwise
                const tail = (otherBytes[otherFullBytes] >>> (8 - otherRemainderBits))
                    // eslint-disable-next-line no-bitwise
                    & ((1 << otherRemainderBits) - 1);
                this.write(tail, otherRemainderBits);
            }

            return;
        }

        if (aligned) {
            for (let i = 0; i < buffer.length; i++) {
                this._bytes.push(buffer[i]);
            }

            this._bitLength += buffer.length * 8;
            return;
        }

        for (let i = 0; i < buffer.length; i++) {
            this.write(buffer[i], 8);
        }
    }

    /**
     * Current write position, in **bytes** (floor of the bit length). Used
     * by name compression to record the byte offset of a label that's
     * about to be written.
     */
    public getByteOffset(): number {
        // eslint-disable-next-line no-bitwise
        return this._bitLength >> 3;
    }

    /**
     * Return the byte offset of a previously written domain name suffix.
     */
    public getNameOffset(name: string): number|undefined {
        return this._nameOffsets.get(name);
    }

    /**
     * Register a domain name suffix at a byte offset for compression.
     */
    public setNameOffset(name: string, offset: number): void {
        this._nameOffsets.set(name, offset);
    }

    /**
     * Materialize the written content as a `Buffer`. If the bit length is
     * not a multiple of 8, the last byte is padded on the right with zeros
     * (matching the original implementation, which split into 8-element
     * chunks and `parseInt`'d each one as binary).
     */
    public toBuffer(): Buffer {
        return Buffer.from(this._bytes);
    }

}