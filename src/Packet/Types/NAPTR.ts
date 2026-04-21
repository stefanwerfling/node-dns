import { Buffer } from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketName} from '../PacketName.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * NAPTR - Naming Authority Pointer
 * @docs https://tools.ietf.org/html/rfc3403
 */
export class NAPTR extends PacketType {

    public order: number;
    public preference: number;
    public flags: string;
    public services: string;
    public regexp: string;
    public replacement: string;

    public constructor(
        order: number = 0,
        preference: number = 0,
        flags: string = '',
        services: string = '',
        regexp: string = '',
        replacement: string = ''
    ) {
        super(PacketTypes.NAPTR);
        this.order = order;
        this.preference = preference;
        this.flags = flags;
        this.services = services;
        this.regexp = regexp;
        this.replacement = replacement;
    }

    /**
     * Read a character-string (1-byte length prefix + data)
     * @param {BufferReader} reader
     * @return {string}
     */
    private static _readCharString(reader: BufferReader): string {
        const len = reader.read(8);
        const chars: number[] = [];

        for (let i = 0; i < len; i++) {
            chars.push(reader.read(8));
        }

        return Buffer.from(chars).toString('utf8');
    }

    /**
     * Write a character-string (1-byte length prefix + data)
     * @param {BufferWriter} writer
     * @param {string} str
     */
    private static _writeCharString(writer: BufferWriter, str: string): void {
        const buf = Buffer.from(str, 'utf8');
        writer.write(buf.length, 8);

        for (const byte of buf) {
            writer.write(byte, 8);
        }
    }

    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        // Build rdata in temp writer to get accurate rdlength
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

    public static decode(reader: BufferReader): PacketType {
        const order = reader.read(16);
        const preference = reader.read(16);
        const flags = NAPTR._readCharString(reader);
        const services = NAPTR._readCharString(reader);
        const regexp = NAPTR._readCharString(reader);
        const replacement = PacketName.decode(reader);

        return new NAPTR(order, preference, flags, services, regexp, replacement);
    }

}