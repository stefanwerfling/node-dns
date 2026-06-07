import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketName } from '../PacketName.js';
import { EdnsOptionCode } from './EdnsECS.js';
export class EdnsChain {
    ednsCode = EdnsOptionCode.CHAIN;
    closestTrustPoint;
    constructor(closestTrustPoint = '') {
        this.closestTrustPoint = closestTrustPoint;
    }
    static decode(reader, length) {
        if (length === 0) {
            return new EdnsChain('');
        }
        const name = PacketName.decode(reader);
        return new EdnsChain(name);
    }
    encode(writer) {
        if (this.closestTrustPoint.length === 0) {
            return;
        }
        const inner = new BufferWriter();
        PacketName.encode(this.closestTrustPoint, inner);
        writer.writeBuffer(inner);
    }
}
//# sourceMappingURL=EdnsChain.js.map