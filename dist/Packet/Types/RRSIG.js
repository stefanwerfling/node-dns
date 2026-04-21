import { PacketName } from '../PacketName.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class RRSIG extends PacketType {
    sigType;
    algorithm;
    labels;
    originalTtl;
    expiration;
    inception;
    keyTag;
    signer;
    signature;
    constructor() {
        super(PacketTypes.RRSIG);
        this.sigType = 0;
        this.algorithm = 0;
        this.labels = 0;
        this.originalTtl = 0;
        this.expiration = '';
        this.inception = '';
        this.keyTag = 0;
        this.signer = '';
        this.signature = '';
    }
    static _dateForSig(timestamp) {
        const date = new Date(timestamp * 1000);
        const month = (date.getUTCMonth() + 1).toString().padStart(2, '0');
        const day = date.getUTCDate().toString().padStart(2, '0');
        const hour = date.getUTCHours().toString().padStart(2, '0');
        const minutes = date.getUTCMinutes().toString().padStart(2, '0');
        const seconds = date.getUTCSeconds().toString().padStart(2, '0');
        return `${date.getFullYear()}${month}${day}${hour}${minutes}${seconds}`;
    }
    static decode(reader, length) {
        const rrsig = new RRSIG();
        const maxOffset = reader.getOffset() + (length * 8);
        rrsig.sigType = reader.read(16);
        rrsig.algorithm = reader.read(8);
        rrsig.labels = reader.read(8);
        rrsig.originalTtl = reader.read(32);
        rrsig.expiration = RRSIG._dateForSig(reader.read(32));
        rrsig.inception = RRSIG._dateForSig(reader.read(32));
        rrsig.keyTag = reader.read(16);
        rrsig.signer = PacketName.decode(reader);
        const maxLength = (maxOffset - reader.getOffset()) / 8;
        const signatureBytes = [];
        while (signatureBytes.length < maxLength) {
            signatureBytes.push(reader.read(8));
        }
        rrsig.signature = Buffer.from(signatureBytes).toString('base64');
        return rrsig;
    }
}
//# sourceMappingURL=RRSIG.js.map