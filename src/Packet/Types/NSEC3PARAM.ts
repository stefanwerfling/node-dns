import { Buffer } from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * NSEC3PARAM — NSEC3 parameters published at the zone apex.
 *
 * Tells validators which hash algorithm, iteration count and salt the
 * authoritative server used when generating the NSEC3 chain. Wire
 * format is the NSEC3 parameter prefix without the next-hashed-owner
 * field and without the type bit map.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc5155#section-4
 */
export class NSEC3PARAM extends PacketType {

    public hashAlgorithm: number;
    public flags: number;
    public iterations: number;
    /** Hex-encoded salt; empty string means "no salt". */
    public salt: string;

    public constructor(
        hashAlgorithm: number = 0,
        flags: number = 0,
        iterations: number = 0,
        salt: string = ''
    ) {
        super(PacketTypes.NSEC3PARAM);
        this.hashAlgorithm = hashAlgorithm;
        this.flags = flags;
        this.iterations = iterations;
        this.salt = salt;
    }

    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;
        const saltBuf = this.salt.length > 0 ? Buffer.from(this.salt, 'hex') : Buffer.alloc(0);

        // rdlength: 1 (alg) + 1 (flags) + 2 (iter) + 1 (saltLen) + saltLen
        twriter.write(5 + saltBuf.length, 16);
        twriter.write(this.hashAlgorithm, 8);
        twriter.write(this.flags, 8);
        twriter.write(this.iterations, 16);
        twriter.write(saltBuf.length, 8);

        for (const byte of saltBuf) {
            twriter.write(byte, 8);
        }

        return twriter.toBuffer();
    }

    public static decode(reader: BufferReader, _length: number): PacketType {
        const hashAlgorithm = reader.read(8);
        const flags = reader.read(8);
        const iterations = reader.read(16);
        const saltLen = reader.read(8);
        const saltBytes: number[] = [];

        for (let i = 0; i < saltLen; i++) {
            saltBytes.push(reader.read(8));
        }

        const salt = Buffer.from(saltBytes).toString('hex');

        return new NSEC3PARAM(hashAlgorithm, flags, iterations, salt);
    }

}