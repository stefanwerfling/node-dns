import {Buffer} from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * HINFO — Host Information (RFC 1035 §3.3.2). Two `<character-string>`
 * fields: CPU and OS. Historically advertised host hardware / OS so
 * remote callers could format presentation strings; modern use is
 * mostly RFC 8482 — answering ANY queries with `HINFO ("RFC8482" "")`
 * instead of dumping the full RRset.
 *
 * `<character-string>` is a one-byte length followed by up to 255
 * bytes of arbitrary octets. Both fields are limited to 255 bytes
 * each on the wire.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.2
 * @docs https://datatracker.ietf.org/doc/html/rfc8482
 */
export class HINFO extends PacketType {

    public cpu: string;
    public os: string;

    public constructor(cpu: string = '', os: string = '') {
        super(PacketTypes.HINFO);
        this.cpu = cpu;
        this.os = os;
    }

    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
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

    public static decode(reader: BufferReader, length: number): PacketType {
        const cpuLen = reader.read(8);
        let consumed = 1 + cpuLen;
        const cpuBytes: number[] = [];

        for (let i = 0; i < cpuLen; i++) {
            cpuBytes.push(reader.read(8));
        }

        if (consumed >= length) {
            return new HINFO(Buffer.from(cpuBytes).toString('utf8'), '');
        }

        const osLen = reader.read(8);
        consumed += 1 + osLen;
        const osBytes: number[] = [];

        for (let i = 0; i < osLen; i++) {
            osBytes.push(reader.read(8));
        }

        return new HINFO(
            Buffer.from(cpuBytes).toString('utf8'),
            Buffer.from(osBytes).toString('utf8')
        );
    }

}