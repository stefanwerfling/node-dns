import { BufferReader } from '../../Lib/BufferReader.js';
import { PacketType } from '../PacketType.js';
import { DNSKEY } from './DNSKEY.js';
export declare class CDNSKEY extends DNSKEY {
    constructor(flags?: number, protocol?: number, algorithm?: number, key?: string);
    static decode(reader: BufferReader, length: number): PacketType;
}
