import { BufferReader } from '../Lib/BufferReader.js';
import { BufferWriter } from '../Lib/BufferWriter.js';
import { PacketClass } from './PacketClass.js';
import { PacketTypes } from './PacketTypes.js';
export declare class PacketQuestion {
    name: string;
    type: PacketTypes | number;
    class: PacketClass | number;
    constructor(name?: string, type?: PacketTypes | number, cls?: PacketClass | number);
    toBuffer(writer?: BufferWriter | null): Buffer;
    static encode(question: PacketQuestion, writer?: BufferWriter | null): Buffer;
    static decode(reader: BufferReader | Buffer): PacketQuestion;
}
