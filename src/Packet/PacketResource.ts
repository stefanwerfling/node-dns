import { Buffer } from 'buffer';
import util from 'util';
import {BufferReader} from '../Lib/BufferReader.js';
import {BufferWriter} from '../Lib/BufferWriter.js';
import {PacketClass} from './PacketClass.js';
import {PacketName} from './PacketName.js';
import {PacketType} from './PacketType.js';
import {PacketTypeRegistry} from './PacketTypeRegistry.js';

/**
 * Resource record format
 * @docs https://tools.ietf.org/html/rfc1035#section-4.1.3
 */
export class PacketResource {

    /**
     * Name
     */
    public name: string;

    /**
     * PacketType
     */
    public packetType: PacketType;

    /**
     * Class
     */
    public class: PacketClass|number;

    /**
     * Ttl
     */
    public ttl: number;

    /**
     * Constructor
     * @param {string} name
     * @param {PacketType} packetType
     * @param {PacketClass|number} cls
     * @param {number} ttl
     */
    public constructor(
        name: string,
        packetType: PacketType,
        cls: PacketClass|number = PacketClass.ANY,
        ttl: number = 300
    ) {
        this.name = name;
        this.packetType = packetType;
        this.class = cls;
        this.ttl = ttl;
    }

    /**
     * Return a Buffer
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     */
    public toBuffer(writer: BufferWriter|null = null): Buffer {
        return PacketResource.encode(this, writer);
    }

    /**
     * Encode
     * @param {PacketResource} resource
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     */
    public static encode(resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        PacketName.encode(resource.name, twriter);

        twriter.write(resource.packetType.type, 16);
        twriter.write(resource.class, 16);
        twriter.write(resource.ttl, 32);

        return resource.packetType.encode(resource, twriter);
    }

    /**
     * Decode buffer to packet resource
     * @param {BufferReader|Buffer} reader
     * @return {PacketResource}
     */
    public static decode(reader: BufferReader|Buffer): PacketResource {
        const treader = reader instanceof BufferReader ? reader : new BufferReader(reader);

        const name = PacketName.decode(treader);
        const type = treader.read(16);
        const cls = treader.read(16);
        const ttl = treader.read(32);
        const len = treader.read(16);

        const packetType = PacketTypeRegistry.getInstance().getPacketType(type);

        if (packetType === null) {
            throw new Error(util.format('node-dns > unknown parser type: %d by domain: %s', type, name));
        }

        const packet = packetType.decode(treader, len);

        return new PacketResource(name, packet, cls, ttl);
    }

}