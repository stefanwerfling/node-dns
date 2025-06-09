import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketName } from '../PacketName.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class MX extends PacketType {
    exchange;
    priority;
    constructor(exchange = '', priority = 0) {
        super(PacketTypes.MX);
        this.exchange = exchange;
        this.priority = priority;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const buffer = PacketName.encode(this.exchange, null);
        twriter.write(buffer.length + 2, 16);
        twriter.write(this.priority, 16);
        twriter.writeBuffer(buffer);
        return twriter.toBuffer();
    }
    static decode(reader) {
        const priority = reader.read(16);
        const exchange = PacketName.decode(reader);
        return new MX(exchange, priority);
    }
}
//# sourceMappingURL=MX.js.map