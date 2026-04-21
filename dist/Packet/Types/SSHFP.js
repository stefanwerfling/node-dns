import { Buffer } from 'buffer';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class SSHFP extends PacketType {
    algorithm;
    fpType;
    fingerprint;
    constructor(algorithm = 0, fpType = 0, fingerprint = '') {
        super(PacketTypes.SSHFP);
        this.algorithm = algorithm;
        this.fpType = fpType;
        this.fingerprint = fingerprint;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const fpBuf = Buffer.from(this.fingerprint, 'hex');
        twriter.write(2 + fpBuf.length, 16);
        twriter.write(this.algorithm, 8);
        twriter.write(this.fpType, 8);
        for (const byte of fpBuf) {
            twriter.write(byte, 8);
        }
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const algorithm = reader.read(8);
        const fpType = reader.read(8);
        const fpLen = length - 2;
        const fpBytes = [];
        for (let i = 0; i < fpLen; i++) {
            fpBytes.push(reader.read(8));
        }
        const fingerprint = Buffer.from(fpBytes).toString('hex');
        return new SSHFP(algorithm, fpType, fingerprint);
    }
}
//# sourceMappingURL=SSHFP.js.map