import { Buffer } from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {IP} from '../IP.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * AAAA
 * @docs https://en.wikipedia.org/wiki/IPv6
 */
export class AAAA extends PacketType {

    /**
     * Address for AAAA
     */
    public address: string;

    /**
     * Constructor
     * @param {string} address
     */
    public constructor(address: string = '') {
        super(PacketTypes.AAAA);
        this.address = address;
    }

    /**
     * Encode AAAA Packet
     * @param {PacketResource} _resource
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     */
    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        const parts = IP.fromIPv6(this.address);

        twriter.write(parts.length * 2, 16);

        parts.forEach((part) => {
            twriter.write(parseInt(`${part}`, 16), 16);
        });

        return twriter.toBuffer();
    }

    /**
     * Decode the Buffer to AAAA Packet
     * @param {BufferReader} reader
     * @param {number} length
     * @return {PacketType}
     */
    public static decode(reader: BufferReader, length: number): PacketType {
        const parts: number[] = [];
        let tlength = length;

        while (tlength) {
            tlength -= 2;
            parts.push(reader.read(16));
        }

        const address = IP.toIPv6(parts);

        return new AAAA(address);
    }

}