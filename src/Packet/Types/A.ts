import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * A Packet
 * @docs https://tools.ietf.org/html/rfc1035#section-3.4.1
 */
export class A extends PacketType {

    /**
     * Address for A
     */
    public address: string;

    /**
     * Constructor
     * @param {string} address
     */
    public constructor(address: string = '') {
        super(PacketTypes.A);
        this.address = address;
    }

    /**
     * Encode A Packet
     * @param {PacketResource} resource
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     */
    public encode(resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        const parts = this.address.split('.');

        twriter.write(parts.length, 16);

        parts.forEach((part) => {
            twriter.write(parseInt(part, 10), 8);
        });

        return twriter.toBuffer();
    }

    /**
     * Decode the Buffer to A Packet
     * @param {BufferReader} reader
     * @param {number} length
     * @return {PacketType}
     */
    public static decode(reader: BufferReader, length: number): PacketType {
        const parts = [];

        while (length--) {
            parts.push(reader.read(8));
        }

        return new A(parts.join('.'));
    }
}