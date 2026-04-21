import { Buffer } from 'buffer';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketName } from '../PacketName.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class NAPTR extends PacketType {
    order;
    preference;
    flags;
    services;
    regexp;
    replacement;
    constructor(order = 0, preference = 0, flags = '', services = '', regexp = '', replacement = '') {
        super(PacketTypes.NAPTR);
        this.order = order;
        this.preference = preference;
        this.flags = flags;
        this.services = services;
        this.regexp = regexp;
        this.replacement = replacement;
    }
    static _readCharString(reader) {
        const len = reader.read(8);
        const chars = [];
        for (let i = 0; i < len; i++) {
            chars.push(reader.read(8));
        }
        return Buffer.from(chars).toString('utf8');
    }
    static _writeCharString(writer, str) {
        const buf = Buffer.from(str, 'utf8');
        writer.write(buf.length, 8);
        for (const byte of buf) {
            writer.write(byte, 8);
        }
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const rdataWriter = new BufferWriter();
        rdataWriter.write(this.order, 16);
        rdataWriter.write(this.preference, 16);
        NAPTR._writeCharString(rdataWriter, this.flags);
        NAPTR._writeCharString(rdataWriter, this.services);
        NAPTR._writeCharString(rdataWriter, this.regexp);
        PacketName.encode(this.replacement, rdataWriter);
        const rdataBuf = rdataWriter.toBuffer();
        twriter.write(rdataBuf.length, 16);
        twriter.writeBuffer(rdataWriter);
        return twriter.toBuffer();
    }
    static decode(reader) {
        const order = reader.read(16);
        const preference = reader.read(16);
        const flags = NAPTR._readCharString(reader);
        const services = NAPTR._readCharString(reader);
        const regexp = NAPTR._readCharString(reader);
        const replacement = PacketName.decode(reader);
        return new NAPTR(order, preference, flags, services, regexp, replacement);
    }
}
//# sourceMappingURL=NAPTR.js.map