import { Buffer } from 'buffer';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class DS extends PacketType {
    keyTag;
    algorithm;
    digestType;
    digest;
    constructor(keyTag = 0, algorithm = 0, digestType = 0, digest = '') {
        super(PacketTypes.DS);
        this.keyTag = keyTag;
        this.algorithm = algorithm;
        this.digestType = digestType;
        this.digest = digest;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const digestBuf = Buffer.from(this.digest, 'hex');
        twriter.write(4 + digestBuf.length, 16);
        twriter.write(this.keyTag, 16);
        twriter.write(this.algorithm, 8);
        twriter.write(this.digestType, 8);
        for (const byte of digestBuf) {
            twriter.write(byte, 8);
        }
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const keyTag = reader.read(16);
        const algorithm = reader.read(8);
        const digestType = reader.read(8);
        const digestLen = length - 4;
        const digestBytes = [];
        for (let i = 0; i < digestLen; i++) {
            digestBytes.push(reader.read(8));
        }
        const digest = Buffer.from(digestBytes).toString('hex');
        return new DS(keyTag, algorithm, digestType, digest);
    }
}
//# sourceMappingURL=DS.js.map