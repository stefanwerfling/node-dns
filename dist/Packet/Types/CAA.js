import { Buffer } from 'buffer';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class CAA extends PacketType {
    flags;
    tag;
    value;
    constructor(flags = 0, tag = '', value = '') {
        super(PacketTypes.CAA);
        this.flags = flags;
        this.tag = tag;
        this.value = value;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const buffer = Buffer.from(this.tag + this.value, 'utf8');
        twriter.write(2 + buffer.length, 16);
        twriter.write(this.flags, 8);
        twriter.write(this.tag.length, 8);
        buffer.forEach((c) => {
            twriter.write(c, 8);
        });
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const flags = reader.read(8);
        const tagLen = reader.read(8);
        const bufferTag = Buffer.alloc(tagLen);
        for (let i = 0; i < tagLen; i++) {
            bufferTag[i] = reader.read(8);
        }
        const tag = bufferTag.toString('utf8');
        const valueLen = length - 2 - tagLen;
        const bufferValue = Buffer.alloc(valueLen);
        for (let i = 0; i < valueLen; i++) {
            bufferValue[i] = reader.read(8);
        }
        const value = bufferValue.toString('utf8');
        return new CAA(flags, tag, value);
    }
}
//# sourceMappingURL=CAA.js.map