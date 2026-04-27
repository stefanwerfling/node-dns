import { Buffer } from 'buffer';

/**
 * Bit-precise reader over a byte buffer. DNS messages have a few sub-byte
 * fields in the 12-byte header (1-bit flags, 4-bit OPCODE/RCODE) and are
 * byte-aligned everywhere else, so this reader takes a fast path for the
 * common case (aligned 8/16/32-bit reads via Node's native Buffer methods)
 * and falls back to byte-shift arithmetic for sub-byte fields.
 *
 * The whole API is bit-precise — `read(size)` and `setOffset(offset)` both
 * operate on bits — so DNS name compression pointers (which point at byte
 * offsets but are read out as 14 bits within a 16-bit field) keep working.
 */
export class BufferReader {

    /**
     * Underlying byte buffer.
     * @protected
     */
    protected _buffer: Buffer;

    /**
     * Current read position, in **bits**.
     * @protected
     */
    protected _offset: number = 0;

    public constructor(buffer: Buffer, offset: number = 0) {
        this._buffer = buffer;
        this._offset = offset || 0;
    }

    /**
     * Stateless read of `length` bits starting at bit `offset` in `buffer`.
     * Used by `PacketHeader.parse` and any other call site that wants to
     * peek without keeping reader state.
     */
    public static read(buffer: Buffer, offset: number, length: number): number {
        // eslint-disable-next-line no-bitwise
        const byteOffset = offset >> 3;
        // eslint-disable-next-line no-bitwise
        const bitInByte = offset & 7;

        // Byte-aligned hot path for the three common DNS field widths.
        if (bitInByte === 0) {
            if (length === 8) {
                return buffer.readUInt8(byteOffset);
            }

            if (length === 16) {
                return buffer.readUInt16BE(byteOffset);
            }

            if (length === 32) {
                return buffer.readUInt32BE(byteOffset);
            }
        }

        // Cold path: arbitrary bit-aligned read. Walks each byte that
        // contains part of the field, shifts bits into place, masks down
        // to `length` bits.
        let value = 0;
        let bitsNeeded = length;
        let curByte = byteOffset;
        let curBitInByte = bitInByte;

        while (bitsNeeded > 0) {
            const bitsInThisByte = 8 - curBitInByte;
            const take = bitsInThisByte < bitsNeeded ? bitsInThisByte : bitsNeeded;
            const shift = bitsInThisByte - take;
            // eslint-disable-next-line no-bitwise
            const mask = (1 << take) - 1;
            // eslint-disable-next-line no-bitwise
            const bits = (buffer[curByte] >> shift) & mask;
            // eslint-disable-next-line no-bitwise
            value = (value << take) | bits;

            bitsNeeded -= take;
            curBitInByte += take;

            if (curBitInByte === 8) {
                curBitInByte = 0;
                curByte++;
            }
        }

        return value;
    }

    /**
     * Read `size` bits at the current offset and advance.
     */
    public read(size: number): number {
        const val = BufferReader.read(this._buffer, this._offset, size);
        this._offset += size;
        return val;
    }

    /**
     * Current read position, in bits.
     */
    public getOffset(): number {
        return this._offset;
    }

    /**
     * Move the read position to `offset` bits. Used by name-compression
     * decoding to follow pointers and rewind back.
     */
    public setOffset(offset: number): void {
        this._offset = offset;
    }

}