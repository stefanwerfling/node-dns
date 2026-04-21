import { Buffer } from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketName} from '../PacketName.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * NSEC - Next Secure Record
 * @docs https://tools.ietf.org/html/rfc4034#section-4
 */
export class NSEC extends PacketType {

    public nextDomain: string;
    public rdtypes: number[];

    public constructor(nextDomain: string = '', rdtypes: number[] = []) {
        super(PacketTypes.NSEC);
        this.nextDomain = nextDomain;
        this.rdtypes = rdtypes;
    }

    /**
     * Parse type bit maps (RFC 4034 Section 4.1.2)
     * @param {BufferReader} reader
     * @param {number} length - remaining bytes
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

    /**
     * Encode type bit maps
     * @param {BufferWriter} writer
     * @param {number[]} types
     */
    private static _encodeTypeBitMaps(writer: BufferWriter, types: number[]): void {
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

    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        // Build rdata in temp writer to get accurate rdlength
        const rdataWriter = new BufferWriter();
        PacketName.encode(this.nextDomain, rdataWriter);
        NSEC._encodeTypeBitMaps(rdataWriter, this.rdtypes);
        const rdataBuf = rdataWriter.toBuffer();

        twriter.write(rdataBuf.length, 16);

        for (const byte of rdataBuf) {
            twriter.write(byte, 8);
        }

        return twriter.toBuffer();
    }

    public static decode(reader: BufferReader, length: number): PacketType {
        const startOffset = reader.getOffset();
        const nextDomain = PacketName.decode(reader);
        const nameLen = (reader.getOffset() - startOffset) / 8;
        const remaining = length - nameLen;
        const rdtypes = NSEC._decodeTypeBitMaps(reader, remaining);

        return new NSEC(nextDomain, rdtypes);
    }

}