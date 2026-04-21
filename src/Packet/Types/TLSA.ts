import { Buffer } from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * TLSA - TLS Certificate Association
 * @docs https://tools.ietf.org/html/rfc6698
 */
export class TLSA extends PacketType {

    public usage: number;
    public selector: number;
    public matchingType: number;
    public certificate: string;

    public constructor(
        usage: number = 0,
        selector: number = 0,
        matchingType: number = 0,
        certificate: string = ''
    ) {
        super(PacketTypes.TLSA);
        this.usage = usage;
        this.selector = selector;
        this.matchingType = matchingType;
        this.certificate = certificate;
    }

    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        const certBuf = Buffer.from(this.certificate, 'hex');

        twriter.write(3 + certBuf.length, 16);
        twriter.write(this.usage, 8);
        twriter.write(this.selector, 8);
        twriter.write(this.matchingType, 8);

        for (const byte of certBuf) {
            twriter.write(byte, 8);
        }

        return twriter.toBuffer();
    }

    public static decode(reader: BufferReader, length: number): PacketType {
        const usage = reader.read(8);
        const selector = reader.read(8);
        const matchingType = reader.read(8);

        const certLen = length - 3;
        const certBytes: number[] = [];

        for (let i = 0; i < certLen; i++) {
            certBytes.push(reader.read(8));
        }

        const certificate = Buffer.from(certBytes).toString('hex');

        return new TLSA(usage, selector, matchingType, certificate);
    }

}