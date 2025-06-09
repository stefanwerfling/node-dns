import { BufferWriter } from '../../Lib/BufferWriter.js';
import { IP } from '../IP.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class AAAA extends PacketType {
    address;
    constructor(address = '') {
        super(PacketTypes.AAAA);
        this.address = address;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const parts = IP.fromIPv6(this.address);
        twriter.write(parts.length * 2, 16);
        parts.forEach((part) => {
            twriter.write(parseInt(`${part}`, 16), 16);
        });
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const parts = [];
        let tlength = length;
        while (tlength) {
            tlength -= 2;
            parts.push(reader.read(16));
        }
        const address = IP.toIPv6(parts);
        return new AAAA(address);
    }
}
//# sourceMappingURL=AAAA.js.map