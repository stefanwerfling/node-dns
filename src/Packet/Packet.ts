import {BufferReader} from '../Lib/BufferReader.js';
import {PacketHeader} from './PacketHeader.js';

export class Packet {

    public header: PacketHeader;

    public questions: PacketQuestions;

    public constructor(data: Packet|PacketHeader|null = null) {
        if (data instanceof Packet) {
            this.header = data.header;
        } else if (data instanceof PacketHeader) {
            this.header = data;
        } else {
            this.header = new PacketHeader();
        }
    }

    public static parse(buffer: Buffer): Packet {
        const packet = new Packet();
        const reader = new BufferReader(buffer);
        packet.header = PacketHeader.parse(reader);

        
    }

}