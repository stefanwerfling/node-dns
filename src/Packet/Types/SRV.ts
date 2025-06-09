import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketName} from '../PacketName.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * SRV Record
 * @docs https://tools.ietf.org/html/rfc2782
 */
export class SRV extends PacketType {

    /**
     * Priority
     */
    public priority: number;

    /**
     * Weight
     */
    public weight: number;

    /**
     * Port
     */
    public port: number;

    /**
     * Target
     */
    public target: string;

    /**
     * Constructor
     * @param {number} priority
     * @param {number} weight
     * @param {number} port
     * @param {string} target
     */
    public constructor(priority: number = 0, weight: number = 0, port: number = 0, target: string = '') {
        super(PacketTypes.SRV);
        this.priority = priority;
        this.weight = weight;
        this.port = port;
        this.target = target;
    }

    /**
     * encode
     * @param {PacketResource} resource
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     * @exception {Error}
     */
    public encode(resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;
        const targetBuffer = PacketName.encode(this.target);

        twriter.write(targetBuffer.length + 6, 16);
        twriter.write(this.priority, 16);
        twriter.write(this.weight, 16);
        twriter.write(this.port, 16);
        twriter.writeBuffer(targetBuffer);

        return twriter.toBuffer();
    }

    /**
     * decode
     * @param {BufferReader} reader
     * @return {PacketType}
     * @exception {Error}
     */
    public static decode(reader: BufferReader): PacketType {
        const priority = reader.read(16);
        const weight = reader.read(16);
        const port = reader.read(16);
        const target = PacketName.decode(reader);

        return new SRV(priority, weight, port, target);
    }

}