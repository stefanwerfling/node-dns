import util from 'util';
import { BufferReader } from '../Lib/BufferReader.js';
import { BufferWriter } from '../Lib/BufferWriter.js';
import { PacketClass } from './PacketClass.js';
import { PacketName } from './PacketName.js';
import { PacketTypeRegistry } from './PacketTypeRegistry.js';
export class PacketResource {
    name;
    packetType;
    class;
    ttl;
    constructor(name, packetType, cls = PacketClass.ANY, ttl = 300) {
        this.name = name;
        this.packetType = packetType;
        this.class = cls;
        this.ttl = ttl;
    }
    toBuffer(writer = null) {
        return PacketResource.encode(this, writer);
    }
    static encode(resource, writer = null) {
        const twriter = writer === null ? new BufferWriter() : writer;
        PacketName.encode(resource.name, twriter);
        twriter.write(resource.packetType.type, 16);
        twriter.write(resource.class, 16);
        twriter.write(resource.ttl, 32);
        return resource.packetType.encode(resource, twriter);
    }
    static decode(reader) {
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
//# sourceMappingURL=PacketResource.js.map