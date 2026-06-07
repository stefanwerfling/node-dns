import { Buffer } from 'buffer';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class URI extends PacketType {
    priority;
    weight;
    target;
    constructor(priority = 0, weight = 0, target = '') {
        super(PacketTypes.URI);
        this.priority = priority;
        this.weight = weight;
        this.target = target;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const targetBuf = Buffer.from(this.target, 'utf8');
        const rdlen = 4 + targetBuf.length;
        twriter.write(rdlen, 16);
        twriter.write(this.priority, 16);
        twriter.write(this.weight, 16);
        for (const byte of targetBuf) {
            twriter.write(byte, 8);
        }
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const priority = reader.read(16);
        const weight = reader.read(16);
        const targetLen = length - 4;
        const targetBytes = [];
        for (let i = 0; i < targetLen; i++) {
            targetBytes.push(reader.read(8));
        }
        return new URI(priority, weight, Buffer.from(targetBytes).toString('utf8'));
    }
}
//# sourceMappingURL=URI.js.map