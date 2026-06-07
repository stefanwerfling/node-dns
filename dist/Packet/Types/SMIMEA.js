import { PacketTypes } from '../PacketTypes.js';
import { TLSA } from './TLSA.js';
export class SMIMEA extends TLSA {
    constructor(usage = 0, selector = 0, matchingType = 0, certificate = '') {
        super(usage, selector, matchingType, certificate);
        this.type = PacketTypes.SMIMEA;
    }
    static decode(reader, length) {
        const tlsa = TLSA.decode(reader, length);
        return new SMIMEA(tlsa.usage, tlsa.selector, tlsa.matchingType, tlsa.certificate);
    }
}
//# sourceMappingURL=SMIMEA.js.map