import { BufferReader } from '../../Lib/BufferReader.js';
import { PacketType } from '../PacketType.js';
import { TLSA } from './TLSA.js';
export declare class SMIMEA extends TLSA {
    constructor(usage?: number, selector?: number, matchingType?: number, certificate?: string);
    static decode(reader: BufferReader, length: number): PacketType;
}
