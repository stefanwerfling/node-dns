import {Buffer} from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * URI — RFC 7553. Publishes a single URI (any scheme) for an owner
 * name with `priority` / `weight` SRV-style selection across multiple
 * RRs of the same RRset.
 *
 * Wire format:
 *
 * ```
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |        Priority         |         Weight       |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  /                        Target                  /
 *  /                                                /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * ```
 *
 * Target is the URI as raw octets — **not** a `<character-string>`,
 * so no length prefix and no compression; consume to end of RDATA.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc7553
 */
export class URI extends PacketType {

    public priority: number;
    public weight: number;
    public target: string;

    public constructor(priority: number = 0, weight: number = 0, target: string = '') {
        super(PacketTypes.URI);
        this.priority = priority;
        this.weight = weight;
        this.target = target;
    }

    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        const targetBuf = Buffer.from(this.target, 'utf8');
        const rdlen = 4 + targetBuf.length;

        twriter.write(rdlen, 16);
        twriter.write(this.priority, 16);
        twriter.write(this.weight, 16);

        for (const byte of targetBuf) {
            twriter.write(byte, 8);
        }

        return twriter.toBuffer();
    }

    public static decode(reader: BufferReader, length: number): PacketType {
        const priority = reader.read(16);
        const weight = reader.read(16);

        const targetLen = length - 4;
        const targetBytes: number[] = [];

        for (let i = 0; i < targetLen; i++) {
            targetBytes.push(reader.read(8));
        }

        return new URI(priority, weight, Buffer.from(targetBytes).toString('utf8'));
    }

}