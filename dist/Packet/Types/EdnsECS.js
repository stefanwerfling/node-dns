export var EdnsOptionCode;
(function (EdnsOptionCode) {
    EdnsOptionCode[EdnsOptionCode["NSID"] = 3] = "NSID";
    EdnsOptionCode[EdnsOptionCode["ECS"] = 8] = "ECS";
    EdnsOptionCode[EdnsOptionCode["COOKIE"] = 10] = "COOKIE";
    EdnsOptionCode[EdnsOptionCode["KEEPALIVE"] = 11] = "KEEPALIVE";
    EdnsOptionCode[EdnsOptionCode["PADDING"] = 12] = "PADDING";
    EdnsOptionCode[EdnsOptionCode["EDE"] = 15] = "EDE";
})(EdnsOptionCode || (EdnsOptionCode = {}));
export class EdnsECS {
    ednsCode = EdnsOptionCode.ECS;
    family;
    sourcePrefixLength;
    scopePrefixLength;
    ip;
    constructor(clientIp = '0.0.0.0/32') {
        const [ip, prefixLength] = clientIp.split('/');
        this.ip = ip;
        this.sourcePrefixLength = parseInt(prefixLength, 10) || 32;
        this.scopePrefixLength = 0;
        this.family = 1;
    }
    static decode(reader, length) {
        const ecs = new EdnsECS();
        ecs.ednsCode = EdnsOptionCode.ECS;
        ecs.family = reader.read(16);
        ecs.sourcePrefixLength = reader.read(8);
        ecs.scopePrefixLength = reader.read(8);
        let remaining = length - 4;
        if (ecs.family === 1) {
            const ipv4Octets = [];
            while (remaining--) {
                ipv4Octets.push(reader.read(8));
            }
            while (ipv4Octets.length < 4) {
                ipv4Octets.push(0);
            }
            ecs.ip = ipv4Octets.join('.');
        }
        if (ecs.family === 2) {
            const ipv6Segments = [];
            for (; remaining > 0; remaining -= 2) {
                ipv6Segments.push(reader.read(16).toString(16));
            }
            while (ipv6Segments.length < 8) {
                ipv6Segments.push('0');
            }
            ecs.ip = ipv6Segments.join(':');
        }
        return ecs;
    }
    encode(writer) {
        const ipParts = this.ip.split('.').map((s) => parseInt(s, 10));
        writer.write(this.family, 16);
        writer.write(this.sourcePrefixLength, 8);
        writer.write(this.scopePrefixLength, 8);
        writer.write(ipParts[0], 8);
        writer.write(ipParts[1], 8);
        writer.write(ipParts[2], 8);
        writer.write(ipParts[3], 8);
    }
}
//# sourceMappingURL=EdnsECS.js.map