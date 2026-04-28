import { BufferReader } from '../../Lib/BufferReader.js';
import { PacketType } from '../PacketType.js';
import { DS } from './DS.js';
export declare class CDS extends DS {
    constructor(keyTag?: number, algorithm?: number, digestType?: number, digest?: string);
    static decode(reader: BufferReader, length: number): PacketType;
}
