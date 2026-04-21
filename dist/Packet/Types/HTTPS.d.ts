import { BufferReader } from '../../Lib/BufferReader.js';
import { PacketType } from '../PacketType.js';
import { SVCB, SvcParams } from './SVCB.js';
export declare class HTTPS extends SVCB {
    constructor(priority?: number, target?: string, params?: SvcParams);
    static decode(reader: BufferReader, length: number): PacketType;
}
