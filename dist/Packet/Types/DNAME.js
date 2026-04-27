import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketName } from '../PacketName.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class DNAME extends PacketType {
    target;
    constructor(target = '') {
        super(PacketTypes.DNAME);
        this.target = target;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const buffer = PacketName.encode(this.target);
        twriter.write(buffer.length, 16);
        twriter.writeBuffer(buffer);
        return twriter.toBuffer();
    }
    static decode(reader) {
        const target = PacketName.decode(reader);
        return new DNAME(target);
    }
}
//# sourceMappingURL=DNAME.js.map