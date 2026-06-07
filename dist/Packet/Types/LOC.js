import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class LOC extends PacketType {
    version;
    size;
    horizPre;
    vertPre;
    latitude;
    longitude;
    altitude;
    constructor(version = 0, size = 0x12, horizPre = 0x16, vertPre = 0x13, latitude = 0, longitude = 0, altitude = 0) {
        super(PacketTypes.LOC);
        this.version = version;
        this.size = size;
        this.horizPre = horizPre;
        this.vertPre = vertPre;
        this.latitude = latitude;
        this.longitude = longitude;
        this.altitude = altitude;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        twriter.write(16, 16);
        twriter.write(this.version, 8);
        twriter.write(this.size, 8);
        twriter.write(this.horizPre, 8);
        twriter.write(this.vertPre, 8);
        twriter.write(this.latitude >>> 0, 32);
        twriter.write(this.longitude >>> 0, 32);
        twriter.write(this.altitude >>> 0, 32);
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        if (length < 16) {
            throw new Error(`LOC: rdlength ${length} too small (need 16)`);
        }
        const version = reader.read(8);
        const size = reader.read(8);
        const horizPre = reader.read(8);
        const vertPre = reader.read(8);
        const latitude = reader.read(32) >>> 0;
        const longitude = reader.read(32) >>> 0;
        const altitude = reader.read(32) >>> 0;
        return new LOC(version, size, horizPre, vertPre, latitude, longitude, altitude);
    }
}
//# sourceMappingURL=LOC.js.map