import { Buffer } from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';
import {debuglog} from 'util';

const debug = debuglog('dns2');

/**
 * EDNS Option Code
 * @docs https://tools.ietf.org/html/rfc6891#section-6.1.2
 */
export enum EdnsOptionCode {
    ECS = 0x08
}

/**
 * EDNS Option
 */
export interface EdnsOption {
    ednsCode: number;
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

/**
 * EDNS
 * @docs https://tools.ietf.org/html/rfc6891
 */
export class EDNS extends PacketType {

    public rdata: EdnsOption[];

    public constructor(rdata: EdnsOption[] = []) {
        super(PacketTypes.EDNS);
        this.rdata = rdata;
    }

    /**
     * Create EDNS resource record data
     * @param {EdnsOption[]} rdata
     * @return {PacketResource}
     */
    public static createResource(rdata: EdnsOption[]): PacketResource {
        return new PacketResource(
            '',
            new EDNS(rdata),
            512,
            0
        );
    }

    /**
     * Encode EDNS Packet
     * @param {PacketResource} _resource
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     */
    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        const rdataWriter = new BufferWriter();

        for (const rdata of this.rdata) {
            if (rdata.ednsCode === EdnsOptionCode.ECS && rdata instanceof EdnsECS) {
                const optWriter = new BufferWriter();
                rdata.encode(optWriter);
                const optBuffer = optWriter.toBuffer();

                rdataWriter.write(rdata.ednsCode, 16);
                rdataWriter.write(optBuffer.length, 16);
                rdataWriter.writeBuffer(optWriter);
            } else {
                debug('node-dns > unknown EDNS rdata encoder %d', rdata.ednsCode);
            }
        }

        const rdataBuffer = rdataWriter.toBuffer();
        twriter.write(rdataBuffer.length, 16);
        twriter.writeBuffer(rdataWriter);

        return twriter.toBuffer();
    }

    /**
     * Decode the Buffer to EDNS Packet
     * @param {BufferReader} reader
     * @param {number} length
     * @return {PacketType}
     */
    public static decode(reader: BufferReader, length: number): PacketType {
        const edns = new EDNS();
        let remaining = length;

        while (remaining > 0) {
            const optionCode = reader.read(16);
            const optionLength = reader.read(16);

            if (optionCode === EdnsOptionCode.ECS) {
                edns.rdata.push(EdnsECS.decode(reader, optionLength));
            } else {
                // Skip unknown option data
                for (let i = 0; i < optionLength; i++) {
                    reader.read(8);
                }

                debug('node-dns > unknown EDNS rdata decoder %d', optionCode);
            }

            remaining = remaining - 4 - optionLength;
        }

        return edns;
    }

}