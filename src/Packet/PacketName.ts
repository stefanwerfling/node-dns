import { Buffer } from 'buffer';
import {BufferReader} from '../Lib/BufferReader.js';
import {BufferWriter} from '../Lib/BufferWriter.js';

export class PacketName {

    public static COPY = 0xc0;

    /**
     * Decode the name
     * @param {BufferReader|Buffer} reader
     * @return {string}
     */
    public static decode(reader: BufferReader|Buffer): string {
        const treader = reader instanceof BufferReader ? reader : new BufferReader(reader);

        const name: string[] = [];

        let o;
        let len = treader.read(8);

        while (len) {
            // eslint-disable-next-line no-bitwise
            if ((len & PacketName.COPY) === PacketName.COPY) {
                len -= PacketName.COPY;
                // eslint-disable-next-line no-bitwise
                len <<= 8;

                const pos = len + treader.read(8);

                if (!o) {
                    o = treader.getOffset();
                }

                treader.setOffset(pos * 8);

                len = treader.read(8);
            } else {
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

    /**
     * Encode the name with optional DNS name compression (RFC 1035 Section 4.1.4).
     * When a shared writer is passed, duplicate domain suffixes are replaced
     * with 2-byte pointers to earlier occurrences.
     * @param {string} domain
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     */
    public static encode(domain: string, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        const labels = (domain || '').split('.').filter((part) => {
            return Boolean(part);
        });

        for (let i = 0; i < labels.length; i++) {
            const suffix = labels.slice(i).join('.');
            const existingOffset = twriter.getNameOffset(suffix);

            if (existingOffset !== undefined) {
                // Write pointer: 2 high bits = 11, remaining 14 bits = byte offset
                // eslint-disable-next-line no-bitwise
                twriter.write(PacketName.COPY | (existingOffset >> 8), 8);
                // eslint-disable-next-line no-bitwise
                twriter.write(existingOffset & 0xFF, 8);

                return twriter.toBuffer();
            }

            // Register this suffix at the current byte offset
            twriter.setNameOffset(suffix, twriter.getByteOffset());

            // Write label length + label characters
            const label = labels[i];
            twriter.write(label.length, 8);

            for (const c of label) {
                twriter.write(c.charCodeAt(0), 8);
            }
        }

        // Write null terminator
        twriter.write(0, 8);

        return twriter.toBuffer();
    }

}