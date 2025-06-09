import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketName} from '../PacketName.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * MX
 * @docs https://tools.ietf.org/html/rfc1035#section-3.3.9
 */
export class MX extends PacketType {

    /**
     * A <domain-name> which specifies a host willing to act as
     * a mail exchange for the owner name.
     */
    public exchange: string;

    /**
     * A 16 bit integer which specifies the preference given to
     * this RR among others at the same owner.  Lower values
     * are preferred.
     */
    public priority: number;

    /**
     * Constructpr
     * @param exchange
     * @param priority
     */
    public constructor(exchange: string = '', priority: number = 0) {
        super(PacketTypes.MX);
        this.exchange = exchange;
        this.priority = priority;
    }

    /**
     * Encode MX Packet
     * @param {PacketResource} resource
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     */
    public encode(resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        const buffer = PacketName.encode(this.exchange, null);

        twriter.write(buffer.length + 2, 16);
        twriter.write(this.priority, 16);
        twriter.writeBuffer(buffer);

        return twriter.toBuffer();
    }

    /**
     * Decode the Buffer to MX Packet
     * @param {BufferReader} reader
     * @return {PacketType}
     */
    public static decode(reader: BufferReader): PacketType {
        const priority = reader.read(16);
        const exchange = PacketName.decode(reader);

        return new MX(exchange, priority);
    }

}