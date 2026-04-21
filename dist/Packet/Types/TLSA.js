import { Buffer } from 'buffer';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class TLSA extends PacketType {
    usage;
    selector;
    matchingType;
    certificate;
    constructor(usage = 0, selector = 0, matchingType = 0, certificate = '') {
        super(PacketTypes.TLSA);
        this.usage = usage;
        this.selector = selector;
        this.matchingType = matchingType;
        this.certificate = certificate;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const certBuf = Buffer.from(this.certificate, 'hex');
        twriter.write(3 + certBuf.length, 16);
        twriter.write(this.usage, 8);
        twriter.write(this.selector, 8);
        twriter.write(this.matchingType, 8);
        for (const byte of certBuf) {
            twriter.write(byte, 8);
        }
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const usage = reader.read(8);
        const selector = reader.read(8);
        const matchingType = reader.read(8);
        const certLen = length - 3;
        const certBytes = [];
        for (let i = 0; i < certLen; i++) {
            certBytes.push(reader.read(8));
        }
        const certificate = Buffer.from(certBytes).toString('hex');
        return new TLSA(usage, selector, matchingType, certificate);
    }
}
//# sourceMappingURL=TLSA.js.map