import { PacketTypes } from '../PacketTypes.js';
import { SVCB } from './SVCB.js';
export class HTTPS extends SVCB {
    constructor(priority = 0, target = '', params = {}) {
        super(priority, target, params);
        this.type = PacketTypes.HTTPS;
    }
    static decode(reader, length) {
        return HTTPS.decodeInto(reader, length, HTTPS);
    }
}
//# sourceMappingURL=HTTPS.js.map