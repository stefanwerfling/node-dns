import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketName } from '../PacketName.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class SRV extends PacketType {
    priority;
    weight;
    port;
    target;
    constructor(priority = 0, weight = 0, port = 0, target = '') {
        super(PacketTypes.SRV);
        this.priority = priority;
        this.weight = weight;
        this.port = port;
        this.target = target;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const targetBuffer = PacketName.encode(this.target);
        twriter.write(targetBuffer.length + 6, 16);
        twriter.write(this.priority, 16);
        twriter.write(this.weight, 16);
        twriter.write(this.port, 16);
        twriter.writeBuffer(targetBuffer);
        return twriter.toBuffer();
    }
    static decode(reader) {
        const priority = reader.read(16);
        const weight = reader.read(16);
        const port = reader.read(16);
        const target = PacketName.decode(reader);
        return new SRV(priority, weight, port, target);
    }
}
//# sourceMappingURL=SRV.js.map