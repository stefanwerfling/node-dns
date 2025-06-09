import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketName } from '../PacketName.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class NS extends PacketType {
    ns;
    constructor(ns = '') {
        super(PacketTypes.NS);
        this.ns = ns;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const buffer = PacketName.encode(this.ns);
        twriter.write(buffer.length, 16);
        twriter.writeBuffer(buffer);
        return twriter.toBuffer();
    }
    static decode(reader) {
        const ns = PacketName.decode(reader);
        return new NS(ns);
    }
}
//# sourceMappingURL=NS.js.map