import { Buffer } from 'buffer';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketType } from '../PacketType.js';
export class UnknownPacketType extends PacketType {
    data;
    constructor(type, data = Buffer.alloc(0)) {
        super(type);
        this.data = data;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        twriter.write(this.data.length, 16);
        for (const byte of this.data) {
            twriter.write(byte, 8);
        }
        return twriter.toBuffer();
    }
}
//# sourceMappingURL=UnknownPacketType.js.map