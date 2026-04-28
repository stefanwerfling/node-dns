import { PacketTypes } from '../PacketTypes.js';
import { DNSKEY } from './DNSKEY.js';
export class CDNSKEY extends DNSKEY {
    constructor(flags = 0, protocol = 0, algorithm = 0, key = '') {
        super(flags, protocol, algorithm, key);
        this.type = PacketTypes.CDNSKEY;
    }
    static decode(reader, length) {
        const dnskey = DNSKEY.decode(reader, length);
        const cdnskey = new CDNSKEY(dnskey.flags, dnskey.protocol, dnskey.algorithm, dnskey.key);
        cdnskey.keyTag = dnskey.keyTag;
        cdnskey.zoneKey = dnskey.zoneKey;
        cdnskey.zoneSep = dnskey.zoneSep;
        return cdnskey;
    }
}
//# sourceMappingURL=CDNSKEY.js.map