import { Buffer } from 'buffer';
import { BufferWriter } from '../../Lib/BufferWriter.js';
import { PacketType } from '../PacketType.js';
import { PacketTypes } from '../PacketTypes.js';
export declare class UnknownPacketType extends PacketType {
    data: Buffer;
    constructor(type: PacketTypes | number, data?: Buffer);
    encode(_resource: unknown, writer?: BufferWriter | null): Buffer;
}
