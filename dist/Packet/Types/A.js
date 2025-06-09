import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class A extends PacketType {
    address;
    constructor(address = '') {
        super(PacketTypes.A);
        this.address = address;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const parts = this.address.split('.');
        twriter.write(parts.length, 16);
        parts.forEach((part) => {
            twriter.write(parseInt(part, 10), 8);
        });
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const parts = [];
        let tLength = length;
        while (tLength--) {
            parts.push(reader.read(8));
        }
        return new A(parts.join('.'));
    }
}
//# sourceMappingURL=A.js.map