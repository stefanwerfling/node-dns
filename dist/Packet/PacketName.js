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
            treader.setOffset(o);
        }
        return name.join('.');
    }
    static encode(domain, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        const labels = (domain || '').split('.').filter((part) => {
            return Boolean(part);
        });
        for (let i = 0; i < labels.length; i++) {
            const suffix = labels.slice(i).join('.');
            const existingOffset = twriter.getNameOffset(suffix);
            if (existingOffset !== undefined) {
                twriter.write(PacketName.COPY | (existingOffset >> 8), 8);
                twriter.write(existingOffset & 0xFF, 8);
                return twriter.toBuffer();
            }
            twriter.setNameOffset(suffix, twriter.getByteOffset());
            const label = labels[i];
            twriter.write(label.length, 8);
            for (const c of label) {
                twriter.write(c.charCodeAt(0), 8);
            }
        }
        twriter.write(0, 8);
        return twriter.toBuffer();
    }
}
//# sourceMappingURL=PacketName.js.map