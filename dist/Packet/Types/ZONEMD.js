import { Buffer } from 'buffer';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class ZONEMD extends PacketType {
    serial;
    scheme;
    hashAlgorithm;
    digest;
    constructor(serial = 0, scheme = 0, hashAlgorithm = 0, digest = '') {
        super(PacketTypes.ZONEMD);
        this.serial = serial;
        this.scheme = scheme;
        this.hashAlgorithm = hashAlgorithm;
        this.digest = digest;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const digestBuf = Buffer.from(this.digest, 'hex');
        const rdlen = 4 + 1 + 1 + digestBuf.length;
        twriter.write(rdlen, 16);
        twriter.write(this.serial >>> 0, 32);
        twriter.write(this.scheme, 8);
        twriter.write(this.hashAlgorithm, 8);
        for (const byte of digestBuf) {
            twriter.write(byte, 8);
        }
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const serial = reader.read(32) >>> 0;
        const scheme = reader.read(8);
        const hashAlgorithm = reader.read(8);
        const digestLen = length - 6;
        const digestBytes = [];
        for (let i = 0; i < digestLen; i++) {
            digestBytes.push(reader.read(8));
        }
        return new ZONEMD(serial, scheme, hashAlgorithm, Buffer.from(digestBytes).toString('hex'));
    }
}
//# sourceMappingURL=ZONEMD.js.map