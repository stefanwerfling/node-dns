import { BufferReader } from '../Lib/BufferReader.js';
import { BufferWriter } from '../Lib/BufferWriter.js';
import { PacketClass } from './PacketClass.js';
import { PacketName } from './PacketName.js';
import { PacketTypes } from './PacketTypes.js';
export class PacketQuestion {
    name;
    type;
    class;
    constructor(name = '', type = PacketTypes.ANY, cls = PacketClass.ANY) {
        this.name = name;
        this.type = type;
        this.class = cls;
    }
    toBuffer(writer = null) {
        return PacketQuestion.encode(this, writer);
    }
    static encode(question, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        PacketName.encode(question.name, twriter);
        twriter.write(question.type, 16);
        twriter.write(question.class, 16);
        return twriter.toBuffer();
    }
    static decode(reader) {
        const treader = reader instanceof BufferReader ? reader : new BufferReader(reader);
        const question = new PacketQuestion();
        question.name = PacketName.decode(treader);
        question.type = treader.read(16);
        question.class = treader.read(16);
        return question;
    }
}
//# sourceMappingURL=PacketQuestion.js.map