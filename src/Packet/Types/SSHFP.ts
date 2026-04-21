import { Buffer } from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * SSHFP - SSH Public Key Fingerprint
 * @docs https://tools.ietf.org/html/rfc4255
 */
export class SSHFP extends PacketType {

    public algorithm: number;
    public fpType: number;
    public fingerprint: string;

    public constructor(algorithm: number = 0, fpType: number = 0, fingerprint: string = '') {
        super(PacketTypes.SSHFP);
        this.algorithm = algorithm;
        this.fpType = fpType;
        this.fingerprint = fingerprint;
    }

    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        const fpBuf = Buffer.from(this.fingerprint, 'hex');

        twriter.write(2 + fpBuf.length, 16);
        twriter.write(this.algorithm, 8);
        twriter.write(this.fpType, 8);

        for (const byte of fpBuf) {
            twriter.write(byte, 8);
        }

        return twriter.toBuffer();
    }

    public static decode(reader: BufferReader, length: number): PacketType {
        const algorithm = reader.read(8);
        const fpType = reader.read(8);

        const fpLen = length - 2;
        const fpBytes: number[] = [];

        for (let i = 0; i < fpLen; i++) {
            fpBytes.push(reader.read(8));
        }

        const fingerprint = Buffer.from(fpBytes).toString('hex');

        return new SSHFP(algorithm, fpType, fingerprint);
    }

}