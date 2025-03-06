import * as util from 'node:util';
import {BufferReader} from '../Lib/BufferReader.js';
import {BufferWriter} from '../Lib/BufferWriter.js';
import {PacketClass} from './PacketClass.js';
import {PacketName} from './PacketName.js';
import {PacketType} from './PacketType.js';
import {PacketTypeRegistry} from './PacketTypeRegistry.js';
import {PacketTypes} from './PacketTypes.js';

/**
 * Resource record format
 * @docs https://tools.ietf.org/html/rfc1035#section-4.1.3
 */
export class PacketResource {

    public name: string;

    public packetType: PacketType;

    public class: PacketClass|number;

    public ttl: number;

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

    public toBuffer(writer: BufferWriter|null = null): Buffer {
        return PacketResource.encode(this, writer);
    }

    /**
     * Encode
     * @param resource
     * @param writer
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
        const treader = reader instanceof Buffer ? new BufferReader(reader) : reader;

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