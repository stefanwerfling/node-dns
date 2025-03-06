import {BufferReader} from '../Lib/BufferReader.js';
import {BufferWriter} from '../Lib/BufferWriter.js';
import {PacketResource} from './PacketResource.js';
import {PacketTypes} from './PacketTypes.js';

export abstract class PacketType {

    public type: PacketTypes|number;

    protected constructor(type: PacketTypes|number) {
        this.type = type;
    }

    public encode(resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        throw new Error('encode() is not implemented');
    }

    public static decode(reader: BufferReader, length: number): PacketType {
        throw new Error('decode() is not implemented');
    }
}