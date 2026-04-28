import { PacketTypes } from '../PacketTypes.js';
import { DS } from './DS.js';
export class CDS extends DS {
    constructor(keyTag = 0, algorithm = 0, digestType = 0, digest = '') {
        super(keyTag, algorithm, digestType, digest);
        this.type = PacketTypes.CDS;
    }
    static decode(reader, length) {
        const ds = DS.decode(reader, length);
        return new CDS(ds.keyTag, ds.algorithm, ds.digestType, ds.digest);
    }
}
//# sourceMappingURL=CDS.js.map