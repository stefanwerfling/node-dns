import { Buffer } from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketName} from '../PacketName.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * PTR
 * @docs https://tools.ietf.org/html/rfc1035#section-3.3.1
 */
export class PTR extends PacketType {

    /**
     * Domain
     */
    public domain: string;

    /**
     * constructor
     * @param {string} domain
     */
    public constructor(domain: string = '') {
        super(PacketTypes.PTR);
        this.domain = domain;
    }

    /**
     * Encode PTR Packet
     * @param {PacketResource} _resource
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     */
    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        const buffer = PacketName.encode(this.domain);

        twriter.write(buffer.length, 16);
        twriter.writeBuffer(buffer);

        return twriter.toBuffer();
    }

    /**
     * Decode the Buffer to PTR Packet
     * @param {BufferReader} reader
     * @return {PacketType}
     */
    public static decode(reader: BufferReader): PacketType {
        const ns = PacketName.decode(reader);

        return new PTR(ns);
    }

}