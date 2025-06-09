import { PacketTypes } from '../PacketTypes.js';
import { TXT } from './TXT.js';
export class SPF extends TXT {
    constructor(data = '') {
        super(data, PacketTypes.SPF);
    }
}
//# sourceMappingURL=SPF.js.map