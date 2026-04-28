import { Buffer } from 'buffer';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class NSEC3PARAM extends PacketType {
    hashAlgorithm;
    flags;
    iterations;
    salt;
    constructor(hashAlgorithm = 0, flags = 0, iterations = 0, salt = '') {
        super(PacketTypes.NSEC3PARAM);
        this.hashAlgorithm = hashAlgorithm;
        this.flags = flags;
        this.iterations = iterations;
        this.salt = salt;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const saltBuf = this.salt.length > 0 ? Buffer.from(this.salt, 'hex') : Buffer.alloc(0);
        twriter.write(5 + saltBuf.length, 16);
        twriter.write(this.hashAlgorithm, 8);
        twriter.write(this.flags, 8);
        twriter.write(this.iterations, 16);
        twriter.write(saltBuf.length, 8);
        for (const byte of saltBuf) {
            twriter.write(byte, 8);
        }
        return twriter.toBuffer();
    }
    static decode(reader, _length) {
        const hashAlgorithm = reader.read(8);
        const flags = reader.read(8);
        const iterations = reader.read(16);
        const saltLen = reader.read(8);
        const saltBytes = [];
        for (let i = 0; i < saltLen; i++) {
            saltBytes.push(reader.read(8));
        }
        const salt = Buffer.from(saltBytes).toString('hex');
        return new NSEC3PARAM(hashAlgorithm, flags, iterations, salt);
    }
}
//# sourceMappingURL=NSEC3PARAM.js.map