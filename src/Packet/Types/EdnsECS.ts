import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';

/**
 * EDNS Option Code
 * @docs https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
 */
export enum EdnsOptionCode {
    NSID = 0x03,
    ECS = 0x08,
    COOKIE = 0x0A,
    KEEPALIVE = 0x0B,
    PADDING = 0x0C,
    CHAIN = 0x0D,
    EDE = 0x0F
}

/**
 * EDNS Option
 */
export interface EdnsOption {
    ednsCode: number;
    encode(writer: BufferWriter): void;
}

/**
 * EDNS ECS (Client Subnet) Option
 * @docs https://tools.ietf.org/html/rfc7871
 */
export class EdnsECS implements EdnsOption {

    public ednsCode: number = EdnsOptionCode.ECS;
    public family: number;
    public sourcePrefixLength: number;
    public scopePrefixLength: number;
    public ip: string;

    public constructor(clientIp: string = '0.0.0.0/32') {
        const [ip, prefixLength] = clientIp.split('/');
        this.ip = ip;
        this.sourcePrefixLength = parseInt(prefixLength, 10) || 32;
        this.scopePrefixLength = 0;
        this.family = 1;
    }

    public static decode(reader: BufferReader, length: number): EdnsECS {
        const ecs = new EdnsECS();
        ecs.ednsCode = EdnsOptionCode.ECS;
        ecs.family = reader.read(16);
        ecs.sourcePrefixLength = reader.read(8);
        ecs.scopePrefixLength = reader.read(8);

        let remaining = length - 4;

        if (ecs.family === 1) {
            const ipv4Octets: number[] = [];

            while (remaining--) {
                ipv4Octets.push(reader.read(8));
            }

            while (ipv4Octets.length < 4) {
                ipv4Octets.push(0);
            }

            ecs.ip = ipv4Octets.join('.');
        }

        if (ecs.family === 2) {
            const ipv6Segments: string[] = [];

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

    public encode(writer: BufferWriter): void {
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