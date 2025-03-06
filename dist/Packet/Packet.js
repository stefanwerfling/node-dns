"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Packet = void 0;
const BufferReader_js_1 = require("../Lib/BufferReader.js");
const BufferWriter_js_1 = require("../Lib/BufferWriter.js");
const PacketHeader_js_1 = require("./PacketHeader.js");
const PacketQuestion_js_1 = require("./PacketQuestion.js");
const PacketResource_js_1 = require("./PacketResource.js");
const util_1 = require("util");
const debug = (0, util_1.debuglog)('dns2');
class Packet {
    header;
    questions = [];
    answers = [];
    authorities = [];
    additionals = [];
    constructor(data = null) {
        if (data instanceof Packet) {
            this.header = data.header;
        }
        else if (data instanceof PacketHeader_js_1.PacketHeader) {
            this.header = data;
        }
        else {
            this.header = new PacketHeader_js_1.PacketHeader();
        }
    }
    toBuffer(writer = null) {
        const twriter = writer === null ? new BufferWriter_js_1.BufferWriter() : writer;
        this.header.qdcount = this.questions.length;
        this.header.ancount = this.answers.length;
        this.header.nscount = this.authorities.length;
        this.header.arcount = this.additionals.length;
        this.header.toBuffer(writer);
        const list = [
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
    static parse(buffer) {
        const packet = new Packet();
        const reader = new BufferReader_js_1.BufferReader(buffer);
        packet.header = PacketHeader_js_1.PacketHeader.parse(reader);
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
                            packet.questions.push(PacketQuestion_js_1.PacketQuestion.decode(reader));
                            break;
                        case 'answers':
                            packet.answers.push(PacketResource_js_1.PacketResource.decode(reader));
                            break;
                        case 'authorities':
                            packet.authorities.push(PacketResource_js_1.PacketResource.decode(reader));
                            break;
                        case 'additionals':
                            packet.authorities.push(PacketResource_js_1.PacketResource.decode(reader));
                            break;
                    }
                }
                catch (e) {
                }
            }
        }
        return packet;
    }
}
exports.Packet = Packet;
//# sourceMappingURL=Packet.js.map