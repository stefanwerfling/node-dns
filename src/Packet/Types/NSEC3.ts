import { Buffer } from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * NSEC3 - Next Secure Record version 3
 * @docs https://tools.ietf.org/html/rfc5155
 */
export class NSEC3 extends PacketType {

    public hashAlgorithm: number;
    public flags: number;
    public iterations: number;
    public salt: string;
    public nextHashedOwner: string;
    public rdtypes: number[];

    public constructor(
        hashAlgorithm: number = 0,
        flags: number = 0,
        iterations: number = 0,
        salt: string = '',
        nextHashedOwner: string = '',
        rdtypes: number[] = []
    ) {
        super(PacketTypes.NSEC3);
        this.hashAlgorithm = hashAlgorithm;
        this.flags = flags;
        this.iterations = iterations;
        this.salt = salt;
        this.nextHashedOwner = nextHashedOwner;
        this.rdtypes = rdtypes;
    }

    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        const saltBuf = this.salt.length > 0 ? Buffer.from(this.salt, 'hex') : Buffer.alloc(0);
        const hashBuf = Buffer.from(this.nextHashedOwner, 'hex');

        // Calculate rdlength: 1+1+2+1+saltLen+1+hashLen+typeBitMaps
        const typeWriter = new BufferWriter();
        NSEC3._encodeTypeBitMaps(typeWriter, this.rdtypes);
        const typeBuf = typeWriter.toBuffer();

        const rdlen = 6 + saltBuf.length + hashBuf.length + typeBuf.length;
        twriter.write(rdlen, 16);
        twriter.write(this.hashAlgorithm, 8);
        twriter.write(this.flags, 8);
        twriter.write(this.iterations, 16);
        twriter.write(saltBuf.length, 8);

        for (const byte of saltBuf) {
            twriter.write(byte, 8);
        }

        twriter.write(hashBuf.length, 8);

        for (const byte of hashBuf) {
            twriter.write(byte, 8);
        }

        for (const byte of typeBuf) {
            twriter.write(byte, 8);
        }

        return twriter.toBuffer();
    }

    /**
     * Encode type bit maps — reuses NSEC logic
     * @param {BufferWriter} writer
     * @param {number[]} types
     */
    private static _encodeTypeBitMaps(writer: BufferWriter, types: number[]): void {
        // Access NSEC's static method via prototype since it's private
        // Duplicate the logic here to avoid visibility issues
        const windows: Map<number, number[]> = new Map();

        for (const rtype of types) {
            // eslint-disable-next-line no-bitwise
            const window = rtype >> 8;
            // eslint-disable-next-line no-bitwise
            const offset = rtype & 0xFF;

            if (!windows.has(window)) {
                windows.set(window, []);
            }

            windows.get(window)!.push(offset);
        }

        for (const [window, offsets] of windows.entries()) {
            const maxOffset = Math.max(...offsets);
            // eslint-disable-next-line no-bitwise
            const bitmapLen = (maxOffset >> 3) + 1;
            const bitmap = Buffer.alloc(bitmapLen);

            for (const offset of offsets) {
                // eslint-disable-next-line no-bitwise
                const byteIndex = offset >> 3;
                // eslint-disable-next-line no-bitwise
                const bitIndex = 7 - (offset & 7);
                // eslint-disable-next-line no-bitwise
                bitmap[byteIndex] |= 1 << bitIndex;
            }

            writer.write(window, 8);
            writer.write(bitmapLen, 8);

            for (const byte of bitmap) {
                writer.write(byte, 8);
            }
        }
    }

    /**
     * Decode type bit maps — reuses same format as NSEC
     * @param {BufferReader} reader
     * @param {number} length
     * @return {number[]}
     */
    private static _decodeTypeBitMaps(reader: BufferReader, length: number): number[] {
        const types: number[] = [];
        let remaining = length;

        while (remaining > 0) {
            const windowBlock = reader.read(8);
            const bitmapLen = reader.read(8);
            remaining -= 2;

            for (let i = 0; i < bitmapLen; i++) {
                const byte = reader.read(8);
                remaining--;

                for (let bit = 0; bit < 8; bit++) {
                    // eslint-disable-next-line no-bitwise
                    if (byte & (1 << (7 - bit))) {
                        types.push((windowBlock * 256) + (i * 8) + bit);
                    }
                }
            }
        }

        return types;
    }

    public static decode(reader: BufferReader, length: number): PacketType {
        const hashAlgorithm = reader.read(8);
        const flags = reader.read(8);
        const iterations = reader.read(16);

        const saltLen = reader.read(8);
        const saltBytes: number[] = [];

        for (let i = 0; i < saltLen; i++) {
            saltBytes.push(reader.read(8));
        }

        const salt = Buffer.from(saltBytes).toString('hex');

        const hashLen = reader.read(8);
        const hashBytes: number[] = [];

        for (let i = 0; i < hashLen; i++) {
            hashBytes.push(reader.read(8));
        }

        const nextHashedOwner = Buffer.from(hashBytes).toString('hex');

        const fixedLen = 5 + saltLen + 1 + hashLen;
        const remaining = length - fixedLen;
        const rdtypes = NSEC3._decodeTypeBitMaps(reader, remaining);

        return new NSEC3(hashAlgorithm, flags, iterations, salt, nextHashedOwner, rdtypes);
    }

}