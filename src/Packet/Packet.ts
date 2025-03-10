import {BufferReader} from '../Lib/BufferReader.js';
import {BufferWriter} from '../Lib/BufferWriter.js';
import {PacketHeader} from './PacketHeader.js';
import {PacketQuestion} from './PacketQuestion.js';
import {PacketResource} from './PacketResource.js';
import {debuglog} from 'util';
import {PacketType} from './PacketType.js';

const debug = debuglog('dns2');

export class Packet {

    public header: PacketHeader;

    public questions: PacketQuestion[] = [];

    public answers: PacketResource[] = [];

    public authorities: PacketResource[] = [];

    public additionals: PacketResource[] = [];

    /**
     * Constructor
     * @param {Packet|PacketHeader|null} data
     */
    public constructor(data: Packet|PacketHeader|null = null) {
        if (data instanceof Packet) {
            this.header = data.header;
        } else if (data instanceof PacketHeader) {
            this.header = data;
        } else {
            this.header = new PacketHeader();
        }
    }

    /**
     * convert a packet to a Buffer
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     */
    public toBuffer(writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        this.header.qdcount = this.questions.length;
        this.header.ancount = this.answers.length;
        this.header.nscount = this.authorities.length;
        this.header.arcount = this.additionals.length;

        this.header.toBuffer(writer);

        const list: string[] = [
            'questions',
            'answers',
            'authorities',
            'additionals'
        ];

        for (const section of list) {
            switch (section) {
                case 'questions':
                    this.questions.map((resource) => {
                        resource.toBuffer(writer);
                    });
                    break;

                case 'answers':
                    this.answers.map((resource) => {
                        resource.toBuffer(writer);
                    });
                    break;

                case 'authorities':
                    this.authorities.map((resource) => {
                        resource.toBuffer(writer);
                    });
                    break;

                case 'additionals':
                    this.additionals.map((resource) => {
                        resource.toBuffer(writer);
                    });
                    break;
            }
        }

        return twriter.toBuffer();
    }

    /**
     * Parse a buffer
     * @param {Buffer} buffer
     * @return {Packet}
     */
    public static parse(buffer: Buffer): Packet {
        const packet = new Packet();
        const reader = new BufferReader(buffer);

        packet.header = PacketHeader.parse(reader);

        const list: Map<string, number> = new Map([
            ['questions', packet.header.qdcount],
            ['answers', packet.header.ancount],
            ['authorities', packet.header.nscount],
            ['additionals', packet.header.arcount]
        ]);

        for (const [section, count] of list.entries()) {
            let tcount = count;

            while (tcount--) {
                try {
                    switch (section) {
                        case 'questions':
                            packet.questions.push(PacketQuestion.decode(reader));
                            break;

                        case 'answers':
                            packet.answers.push(PacketResource.decode(reader));
                            break;

                        case 'authorities':
                            packet.authorities.push(PacketResource.decode(reader));
                            break;

                        case 'additionals':
                            packet.authorities.push(PacketResource.decode(reader));
                            break;
                    }
                } catch (e) {
                    // TODO Error

                }
            }
        }

        return packet;
    }

    /**
     * Helper, create response from Request
     * @param {Packet} request
     * @return {Packet}
     */
    public static createResponseFromRequest(request: Packet): Packet {
        const response = new Packet(request);
        response.header.qr = 1;
        response.additionals = [];
        return response;
    }

    /**
     * Create a Resource from Question
     * @param {PacketQuestion} base
     * @param {PacketType} record
     * @return {PacketResource}
     */
    public static createResourceFromQuestion(base: PacketQuestion, record: PacketType): PacketResource {
        return  new PacketResource(
            base.name,
            record,
            base.class,
            300
        );
    }
}