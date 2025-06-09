export class PacketType {
    type;
    constructor(type) {
        this.type = type;
    }
    encode(resource, writer = null) {
        throw new Error('encode() is not implemented');
    }
    static decode(reader, length) {
        throw new Error('decode() is not implemented');
    }
}
//# sourceMappingURL=PacketType.js.map