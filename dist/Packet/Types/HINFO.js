import { Buffer } from 'buffer';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export class HINFO extends PacketType {
    cpu;
    os;
    constructor(cpu = '', os = '') {
        super(PacketTypes.HINFO);
        this.cpu = cpu;
        this.os = os;
    }
    encode(_resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const cpuBuf = Buffer.from(this.cpu, 'utf8');
        const osBuf = Buffer.from(this.os, 'utf8');
        if (cpuBuf.length > 255 || osBuf.length > 255) {
            throw new Error('HINFO: cpu / os character-string exceeds 255 bytes');
        }
        const rdlen = 1 + cpuBuf.length + 1 + osBuf.length;
        twriter.write(rdlen, 16);
        twriter.write(cpuBuf.length, 8);
        for (const byte of cpuBuf) {
            twriter.write(byte, 8);
        }
        twriter.write(osBuf.length, 8);
        for (const byte of osBuf) {
            twriter.write(byte, 8);
        }
        return twriter.toBuffer();
    }
    static decode(reader, length) {
        const cpuLen = reader.read(8);
        let consumed = 1 + cpuLen;
        const cpuBytes = [];
        for (let i = 0; i < cpuLen; i++) {
            cpuBytes.push(reader.read(8));
        }
        if (consumed >= length) {
            return new HINFO(Buffer.from(cpuBytes).toString('utf8'), '');
        }
        const osLen = reader.read(8);
        consumed += 1 + osLen;
        const osBytes = [];
        for (let i = 0; i < osLen; i++) {
            osBytes.push(reader.read(8));
        }
        return new HINFO(Buffer.from(cpuBytes).toString('utf8'), Buffer.from(osBytes).toString('utf8'));
    }
}
//# sourceMappingURL=HINFO.js.map