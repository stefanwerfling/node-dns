import { Buffer } from 'buffer';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class DNSKEY extends PacketType {
    flags;
    protocol;
    algorithm;
    keyTag;
    zoneKey;
    zoneSep;
    key;
    constructor(flags = 0, protocol = 0, algorithm = 0, key = '') {
        super(PacketTypes.DNSKEY);
        this.flags = flags;
        this.protocol = protocol;
        this.algorithm = algorithm;
        this.key = key;
        this.keyTag = 0;
        this.zoneKey = false;
        this.zoneSep = false;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const keyBuffer = Buffer.from(this.key, 'base64');
        twriter.write(4 + keyBuffer.length, 16);
        twriter.write(this.flags, 16);
        twriter.write(this.protocol, 8);
        twriter.write(this.algorithm, 8);
        for (const c of keyBuffer) {
            twriter.write(c, 8);
        }
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const rdata = [];
        while (rdata.length < length) {
            rdata.push(reader.read(8));
        }
        const dnskey = new DNSKEY();
        dnskey.flags = (rdata[0] << 8) | rdata[1];
        dnskey.protocol = rdata[2];
        dnskey.algorithm = rdata[3];
        let ac = 0;
        for (let i = 0; i < length; ++i) {
            ac += i & 1 ? rdata[i] : rdata[i] << 8;
        }
        ac += (ac >> 16) & 0xFFFF;
        dnskey.keyTag = ac & 0xFFFF;
        let binFlags = dnskey.flags.toString(2);
        while (binFlags.length < 16) {
            binFlags = `0${binFlags}`;
        }
        dnskey.zoneKey = binFlags[7] === '1';
        dnskey.zoneSep = binFlags[15] === '1';
        dnskey.key = Buffer.from(rdata.slice(4)).toString('base64');
        return dnskey;
    }
}
//# sourceMappingURL=DNSKEY.js.map