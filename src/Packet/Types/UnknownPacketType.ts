import { Buffer } from 'buffer';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * Unknown Packet Type - for unregistered record types
 */
export class UnknownPacketType extends PacketType {

    public data: Buffer;

    public constructor(type: PacketTypes|number, data: Buffer = Buffer.alloc(0)) {
        super(type);
        this.data = data;
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    public encode(_resource: unknown, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        twriter.write(this.data.length, 16);

        for (const byte of this.data) {
            twriter.write(byte, 8);
        }

        return twriter.toBuffer();
    }

}