import { BufferReader } from '../Lib/BufferReader.js';
import { BufferWriter } from '../Lib/BufferWriter.js';
import { PacketHeader } from './PacketHeader.js';
import { PacketQuestion } from './PacketQuestion.js';
import { PacketResource } from './PacketResource.js';
import { debuglog } from 'util';
const debug = debuglog('dns2');
export class Packet {
    header;
    questions = [];
    answers = [];
    authorities = [];
    additionals = [];
    constructor(data = null) {
        if (data instanceof Packet) {
            this.header = data.header;
        }
        else if (data instanceof PacketHeader) {
            this.header = data;
        }
        else {
            this.header = new PacketHeader();
        }
    }
    toBuffer(writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        this.header.qdcount = this.questions.length;
        this.header.ancount = this.answers.length;
        this.header.nscount = this.authorities.length;
        this.header.arcount = this.additionals.length;
        this.header.toBuffer(twriter);
        const list = [
            'questions',
            'answers',
            'authorities',
            'additionals'
        ];
        for (const section of list) {
            switch (section) {
                case 'questions':
                    this.questions.forEach((resource) => {
                        resource.toBuffer(twriter);
                    });
                    break;
                case 'answers':
                    this.answers.forEach((resource) => {
                        resource.toBuffer(twriter);
                    });
                    break;
                case 'authorities':
                    this.authorities.forEach((resource) => {
                        resource.toBuffer(twriter);
                    });
                    break;
                case 'additionals':
                    this.additionals.forEach((resource) => {
                        resource.toBuffer(twriter);
                    });
                    break;
            }
        }
        return twriter.toBuffer();
    }
    static parse(buffer) {
        const packet = new Packet();
        const reader = new BufferReader(buffer);
        packet.header = PacketHeader.parse(reader);
        const list = new Map([
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
                            packet.additionals.push(PacketResource.decode(reader));
                            break;
                    }
                }
                catch (e) {
                    if (e instanceof Error) {
                        debug('node-dns > parse %s error:', section, e.message);
                    }
                    else {
                        debug('node-dns > parse %s error: Unknown error', section, e);
                    }
                }
            }
        }
        return packet;
    }
    get recursive() {
        return Boolean(this.header.rd);
    }
    set recursive(yn) {
        this.header.rd = yn ? 1 : 0;
    }
    toBase64URL() {
        const buffer = this.toBuffer();
        const base64 = buffer.toString('base64');
        return base64
            .replace(/[=]/gu, '')
            .replace(/[+]/gu, '-')
            .replace(/[/]/gu, '_');
    }
    static createResponseFromRequest(request) {
        const response = new Packet(request);
        response.header.qr = 1;
        response.additionals = [];
        return response;
    }
    static createResourceFromQuestion(base, record, tls = 300) {
        return new PacketResource(base.name, record, base.class, tls);
    }
}
//# sourceMappingURL=Packet.js.map