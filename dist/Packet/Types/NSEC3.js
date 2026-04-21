import { Buffer } from 'buffer';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class NSEC3 extends PacketType {
    hashAlgorithm;
    flags;
    iterations;
    salt;
    nextHashedOwner;
    rdtypes;
    constructor(hashAlgorithm = 0, flags = 0, iterations = 0, salt = '', nextHashedOwner = '', rdtypes = []) {
        super(PacketTypes.NSEC3);
        this.hashAlgorithm = hashAlgorithm;
        this.flags = flags;
        this.iterations = iterations;
        this.salt = salt;
        this.nextHashedOwner = nextHashedOwner;
        this.rdtypes = rdtypes;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const saltBuf = this.salt.length > 0 ? Buffer.from(this.salt, 'hex') : Buffer.alloc(0);
        const hashBuf = Buffer.from(this.nextHashedOwner, 'hex');
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
    static decode(reader, length) {
        const hashAlgorithm = reader.read(8);
        const flags = reader.read(8);
        const iterations = reader.read(16);
        const saltLen = reader.read(8);
        const saltBytes = [];
        for (let i = 0; i < saltLen; i++) {
            saltBytes.push(reader.read(8));
        }
        const salt = Buffer.from(saltBytes).toString('hex');
        const hashLen = reader.read(8);
        const hashBytes = [];
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
//# sourceMappingURL=NSEC3.js.map