import { Buffer } from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * DS - Delegation Signer
 * @docs https://tools.ietf.org/html/rfc4034#section-5
 */
export class DS extends PacketType {

    public keyTag: number;
    public algorithm: number;
    public digestType: number;
    public digest: string;

    public constructor(
        keyTag: number = 0,
        algorithm: number = 0,
        digestType: number = 0,
        digest: string = ''
    ) {
        super(PacketTypes.DS);
        this.keyTag = keyTag;
        this.algorithm = algorithm;
        this.digestType = digestType;
        this.digest = digest;
    }

    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        const digestBuf = Buffer.from(this.digest, 'hex');

        twriter.write(4 + digestBuf.length, 16);
        twriter.write(this.keyTag, 16);
        twriter.write(this.algorithm, 8);
        twriter.write(this.digestType, 8);

        for (const byte of digestBuf) {
            twriter.write(byte, 8);
        }

        return twriter.toBuffer();
    }

    public static decode(reader: BufferReader, length: number): PacketType {
        const keyTag = reader.read(16);
        const algorithm = reader.read(8);
        const digestType = reader.read(8);

        const digestLen = length - 4;
        const digestBytes: number[] = [];

        for (let i = 0; i < digestLen; i++) {
            digestBytes.push(reader.read(8));
        }

        const digest = Buffer.from(digestBytes).toString('hex');

        return new DS(keyTag, algorithm, digestType, digest);
    }

}