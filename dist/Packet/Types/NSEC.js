import { Buffer } from 'buffer';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketName } from '../PacketName.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class NSEC extends PacketType {
    nextDomain;
    rdtypes;
    constructor(nextDomain = '', rdtypes = []) {
        super(PacketTypes.NSEC);
        this.nextDomain = nextDomain;
        this.rdtypes = rdtypes;
    }
    static _decodeTypeBitMaps(reader, length) {
        const types = [];
        let remaining = length;
        while (remaining > 0) {
            const windowBlock = reader.read(8);
            const bitmapLen = reader.read(8);
            remaining -= 2;
            for (let i = 0; i < bitmapLen; i++) {
                const byte = reader.read(8);
                remaining--;
                for (let bit = 0; bit < 8; bit++) {
                    if (byte & (1 << (7 - bit))) {
                        types.push((windowBlock * 256) + (i * 8) + bit);
                    }
                }
            }
        }
        return types;
    }
    static _encodeTypeBitMaps(writer, types) {
        const windows = new Map();
        for (const rtype of types) {
            const window = rtype >> 8;
            const offset = rtype & 0xFF;
            if (!windows.has(window)) {
                windows.set(window, []);
            }
            windows.get(window).push(offset);
        }
        for (const [window, offsets] of windows.entries()) {
            const maxOffset = Math.max(...offsets);
            const bitmapLen = (maxOffset >> 3) + 1;
            const bitmap = Buffer.alloc(bitmapLen);
            for (const offset of offsets) {
                const byteIndex = offset >> 3;
                const bitIndex = 7 - (offset & 7);
                bitmap[byteIndex] |= 1 << bitIndex;
            }
            writer.write(window, 8);
            writer.write(bitmapLen, 8);
            for (const byte of bitmap) {
                writer.write(byte, 8);
            }
        }
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
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
    static decode(reader, length) {
        const startOffset = reader.getOffset();
        const nextDomain = PacketName.decode(reader);
        const nameLen = (reader.getOffset() - startOffset) / 8;
        const remaining = length - nameLen;
        const rdtypes = NSEC._decodeTypeBitMaps(reader, remaining);
        return new NSEC(nextDomain, rdtypes);
    }
}
//# sourceMappingURL=NSEC.js.map