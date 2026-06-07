import { Buffer } from 'buffer';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class OPENPGPKEY extends PacketType {
    publicKey;
    constructor(publicKey = '') {
        super(PacketTypes.OPENPGPKEY);
        this.publicKey = publicKey;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const keyBuf = Buffer.from(this.publicKey, 'hex');
        twriter.write(keyBuf.length, 16);
        for (const byte of keyBuf) {
            twriter.write(byte, 8);
        }
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const keyBytes = [];
        for (let i = 0; i < length; i++) {
            keyBytes.push(reader.read(8));
        }
        return new OPENPGPKEY(Buffer.from(keyBytes).toString('hex'));
    }
}
//# sourceMappingURL=OPENPGPKEY.js.map