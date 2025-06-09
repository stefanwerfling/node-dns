import { Buffer } from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * CAA
 */
export class CAA extends PacketType {

    /**
     * Flags
     */
    public flags: number;

    /**
     * Tag
     */
    public tag: string;

    /**
     * Value
     */
    public value: string;

    /**
     * Constructor
     * @param {number} flags
     * @param {string} tag
     * @param {string} value
     */
    public constructor(flags: number = 0, tag: string = '', value: string = '') {
        super(PacketTypes.CAA);
        this.flags = flags;
        this.tag = tag;
        this.value = value;
    }

    /**
     * Encode CAA Packet
     * @param {PacketResource} _resource
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     */
    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        const buffer = Buffer.from(this.tag + this.value, 'utf8');
        twriter.write(2 + buffer.length, 16);
        twriter.write(this.flags, 8);
        twriter.write(this.tag.length, 8);

        buffer.forEach((c) => {
            twriter.write(c, 8);
        });

        return twriter.toBuffer();
    }

    /**
     * Decode the Buffer to MX Packet
     * @param {BufferReader} reader
     * @param {number} length
     * @return {PacketType}
     */
    public static decode(reader: BufferReader, length: number): PacketType {
        const flags = reader.read(8);
        const tagLen = reader.read(8);

        const bufferTag = Buffer.alloc(tagLen);

        for (let i = 0; i < tagLen; i++) {
            bufferTag[i] = reader.read(8);
        }

        const tag = bufferTag.toString('utf8');

        const valueLen = length - 2 - tagLen;
        const bufferValue = Buffer.alloc(valueLen);

        for (let i = 0; i < valueLen; i++) {
            bufferValue[i] = reader.read(8);
        }

        const value = bufferValue.toString('utf8');

        return new CAA(flags, tag, value);
    }

}