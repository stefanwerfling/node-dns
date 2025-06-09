import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketName } from '../PacketName.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class CNAME extends PacketType {
    domain;
    constructor(domain = '') {
        super(PacketTypes.CNAME);
        this.domain = domain;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const buffer = PacketName.encode(this.domain);
        twriter.write(buffer.length, 16);
        twriter.writeBuffer(buffer);
        return twriter.toBuffer();
    }
    static decode(reader) {
        const ns = PacketName.decode(reader);
        return new CNAME(ns);
    }
}
//# sourceMappingURL=CNAME.js.map