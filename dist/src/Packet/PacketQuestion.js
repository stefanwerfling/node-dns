"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PacketQuestion = void 0;
const BufferReader_js_1 = require("../Lib/BufferReader.js");
const BufferWriter_js_1 = require("../Lib/BufferWriter.js");
const PacketClass_js_1 = require("./PacketClass.js");
const PacketName_js_1 = require("./PacketName.js");
const PacketTypes_js_1 = require("./PacketTypes.js");
class PacketQuestion {
    name;
    type;
    class;
    constructor(name = '', type = PacketTypes_js_1.PacketTypes.ANY, cls = PacketClass_js_1.PacketClass.ANY) {
        this.name = name;
        this.type = type;
        this.class = cls;
    }
    toBuffer(writer = null) {
        return PacketQuestion.encode(this, writer);
    }
    static encode(question, writer = null) {
        const twriter = writer === null ? new BufferWriter_js_1.BufferWriter() : writer;
        PacketName_js_1.PacketName.encode(question.name, twriter);
        twriter.write(question.type, 16);
        twriter.write(question.class, 16);
        return twriter.toBuffer();
    }
    static decode(reader) {
        const treader = reader instanceof BufferReader_js_1.BufferReader ? reader : new BufferReader_js_1.BufferReader(reader);
        const question = new PacketQuestion();
        question.name = PacketName_js_1.PacketName.decode(treader);
        question.type = treader.read(16);
        question.class = treader.read(16);
        return question;
    }
}
exports.PacketQuestion = PacketQuestion;
//# sourceMappingURL=PacketQuestion.js.map