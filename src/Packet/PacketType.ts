import { Buffer } from 'buffer';
import {BufferReader} from '../Lib/BufferReader.js';
import {BufferWriter} from '../Lib/BufferWriter.js';
import {PacketResource} from './PacketResource.js';
import {PacketTypes} from './PacketTypes.js';

/**
 * Abstract PacketType
 */
export abstract class PacketType {

    /**
     * Type
     */
    public type: PacketTypes|number;

    /**
     * Constructor
     * @param {PacketTypes|number} type
     * @protected
     */
    protected constructor(type: PacketTypes|number) {
        this.type = type;
    }

    /**
     * encode
     * @param {PacketResource} resource
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     * @exception {Error}
     */
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    public encode(resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        throw new Error('encode() is not implemented');
    }

    /**
     * decode
     * @param {BufferReader} reader
     * @param {length} length
     * @return {PacketType}
     * @exception {Error}
     */
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    public static decode(reader: BufferReader, length: number): PacketType {
        throw new Error('decode() is not implemented');
    }

}