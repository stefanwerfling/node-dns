import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketName} from '../PacketName.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * NS
 * @docs https://tools.ietf.org/html/rfc1035#section-3.3.11
 */
export class NS extends PacketType {

    /**
     * NS String
     */
    public ns: string;

    /**
     * Constructor
     * @param {string} ns
     */
    public constructor(ns: string = '') {
        super(PacketTypes.NS);
        this.ns = ns;
    }

    /**
     * Encode NS Packet
     * @param {PacketResource} resource
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     */
    public encode(resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        const buffer = PacketName.encode(this.ns);

        twriter.write(buffer.length, 16);
        twriter.writeBuffer(buffer);

        return twriter.toBuffer();
    }

    /**
     * Decode the Buffer to NS Packet
     * @param {BufferReader} reader
     * @param {number} length
     * @return {PacketType}
     */
    public static decode(reader: BufferReader, length: number): PacketType {
        const ns = PacketName.decode(reader);

        return new NS(ns);
    }

}