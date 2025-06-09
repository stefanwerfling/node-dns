import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketName } from '../PacketName.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class SOA extends PacketType {
    primary;
    admin;
    serial;
    refresh;
    retry;
    expiration;
    minimum;
    constructor(primary = '', admin = '', serial = 0, refresh = 0, retry = 0, expiration = 0, minimum = 0) {
        super(PacketTypes.SOA);
        this.primary = primary;
        this.admin = admin;
        this.serial = serial;
        this.refresh = refresh;
        this.retry = retry;
        this.expiration = expiration;
        this.minimum = minimum;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const namePrimary = PacketName.encode(this.primary);
        const nameAdmin = PacketName.encode(this.admin);
        twriter.write(namePrimary.length + nameAdmin.length + ((32 * 5) / 8), 16);
        twriter.writeBuffer(namePrimary);
        twriter.writeBuffer(nameAdmin);
        twriter.write(this.serial, 32);
        twriter.write(this.refresh, 32);
        twriter.write(this.retry, 32);
        twriter.write(this.expiration, 32);
        twriter.write(this.minimum, 32);
        return twriter.toBuffer();
    }
    static decode(reader) {
        const soa = new SOA();
        soa.primary = PacketName.decode(reader);
        soa.admin = PacketName.decode(reader);
        soa.serial = reader.read(32);
        soa.refresh = reader.read(32);
        soa.retry = reader.read(32);
        soa.expiration = reader.read(32);
        soa.minimum = reader.read(32);
        return soa;
    }
}
//# sourceMappingURL=SOA.js.map