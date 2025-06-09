import { BufferReader } from '../Lib/BufferReader.js';
import { BufferWriter } from '../Lib/BufferWriter.js';
export class PacketName {
    static COPY = 0xc0;
    static decode(reader) {
        const treader = reader instanceof BufferReader ? reader : new BufferReader(reader);
        const name = [];
        let o;
        let len = treader.read(8);
        while (len) {
            if ((len & PacketName.COPY) === PacketName.COPY) {
                len -= PacketName.COPY;
                len <<= 8;
                const pos = len + treader.read(8);
                if (!o) {
                    o = treader.getOffset();
                }
                treader.setOffset(pos * 8);
                len = treader.read(8);
            }
            else {
                let part = '';
                while (len--) {
                    part += String.fromCharCode(treader.read(8));
                }
                name.push(part);
                len = treader.read(8);
            }
        }
        if (o) {
            treader.setOffset(0);
        }
        return name.join('.');
    }
    static encode(domain, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        domain.split('.').filter((part) => {
            return Boolean(part);
        }).forEach((part) => {
            twriter.write(part.length, 8);
            part.split('').map((c) => {
                twriter.write(c.charCodeAt(0), 8);
                return c.charCodeAt(0);
            });
        });
        twriter.write(0, 8);
        return twriter.toBuffer();
    }
}
//# sourceMappingURL=PacketName.js.map