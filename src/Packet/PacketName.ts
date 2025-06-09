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
            treader.setOffset(0);
        }

        return name.join('.');
    }

    /**
     * Encode the name
     * @param {string} domain
     * @param {BufferWriter|null} writer
     */
    public static encode(domain: string, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        // TODO: domain name compress

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