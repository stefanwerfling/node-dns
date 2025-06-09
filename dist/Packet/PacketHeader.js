import { BufferReader } from '../Lib/BufferReader.js';
import { BufferWriter } from '../Lib/BufferWriter.js';
export class PacketHeader {
    id = 0;
    qr = 0;
    opcode = 0;
    aa = 0;
    tc = 0;
    rd = 0;
    ra = 0;
    z = 0;
    rcode = 0;
    qdcount = 0;
    ancount = 0;
    nscount = 0;
    arcount = 0;
    static parse(reader) {
        const tReader = reader instanceof BufferReader ? reader : new BufferReader(reader);
        const header = new PacketHeader();
        header.id = tReader.read(16);
        header.qr = tReader.read(1);
        header.opcode = tReader.read(4);
        header.aa = tReader.read(1);
        header.tc = tReader.read(1);
        header.rd = tReader.read(1);
        header.ra = tReader.read(1);
        header.z = tReader.read(3);
        header.rcode = tReader.read(4);
        header.qdcount = tReader.read(16);
        header.ancount = tReader.read(16);
        header.nscount = tReader.read(16);
        header.arcount = tReader.read(16);
        return header;
    }
    toBuffer(writer = null) {
        const tWriter = writer === null ? new BufferWriter() : writer;
        tWriter.write(this.id, 16);
        tWriter.write(this.qr, 1);
        tWriter.write(this.opcode, 4);
        tWriter.write(this.aa, 1);
        tWriter.write(this.tc, 1);
        tWriter.write(this.rd, 1);
        tWriter.write(this.ra, 1);
        tWriter.write(this.z, 3);
        tWriter.write(this.rcode, 4);
        tWriter.write(this.qdcount, 16);
        tWriter.write(this.ancount, 16);
        tWriter.write(this.nscount, 16);
        tWriter.write(this.arcount, 16);
        return tWriter.toBuffer();
    }
}
//# sourceMappingURL=PacketHeader.js.map