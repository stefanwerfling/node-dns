import { Buffer } from 'buffer';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class CERT extends PacketType {
    certType;
    keyTag;
    algorithm;
    certificate;
    constructor(certType = 0, keyTag = 0, algorithm = 0, certificate = '') {
        super(PacketTypes.CERT);
        this.certType = certType;
        this.keyTag = keyTag;
        this.algorithm = algorithm;
        this.certificate = certificate;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const certBuf = Buffer.from(this.certificate, 'hex');
        const rdlen = 5 + certBuf.length;
        twriter.write(rdlen, 16);
        twriter.write(this.certType, 16);
        twriter.write(this.keyTag, 16);
        twriter.write(this.algorithm, 8);
        for (const byte of certBuf) {
            twriter.write(byte, 8);
        }
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const certType = reader.read(16);
        const keyTag = reader.read(16);
        const algorithm = reader.read(8);
        const certLen = length - 5;
        const certBytes = [];
        for (let i = 0; i < certLen; i++) {
            certBytes.push(reader.read(8));
        }
        return new CERT(certType, keyTag, algorithm, Buffer.from(certBytes).toString('hex'));
    }
}
//# sourceMappingURL=CERT.js.map