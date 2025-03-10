import {BufferReader} from '../Lib/BufferReader.js';
import {BufferWriter} from '../Lib/BufferWriter.js';
import {PacketClass} from './PacketClass.js';
import {PacketName} from './PacketName.js';
import {PacketTypes} from './PacketTypes.js';

/**
 * Question section format
 * @docs https://tools.ietf.org/html/rfc1035#section-4.1.2
 */
export class PacketQuestion {

    /**
     * Domain name
     */
    public name: string;

    /**
     * Type
     */
    public type: PacketTypes|number;

    /**
     * Class
     */
    public class: PacketClass|number;

    /**
     * Constructor
     * @param {string} name
     * @param {PacketTypes|number} type
     * @param {PacketClass|number} cls
     */
    public constructor(name: string = '', type: PacketTypes|number = PacketTypes.ANY, cls: PacketClass|number = PacketClass.ANY) {
        this.name = name;
        this.type = type;
        this.class = cls;
    }

    /**
     * Convert question to Buffer
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     */
    public toBuffer(writer: BufferWriter|null = null): Buffer {
        return PacketQuestion.encode(this, writer);
    }

    /**
     * Question encode
     * @param {PacketQuestion} question
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     */
    public static encode(question: PacketQuestion, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        PacketName.encode(question.name, twriter);

        twriter.write(question.type, 16);
        twriter.write(question.class, 16);

        return twriter.toBuffer();
    }

    /**
     * Question decode
     * @param {BufferReader|Buffer} reader
     * @return {PacketQuestion}
     */
    public static decode(reader: BufferReader|Buffer): PacketQuestion {
        const treader = reader instanceof BufferReader ? reader: new BufferReader(reader);

        const question = new PacketQuestion();
        question.name = PacketName.decode(treader);
        question.type = treader.read(16);
        question.class = treader.read(16);

        return question;

    }

}