import {Buffer} from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * ZONEMD — Message Digest for DNS Zones (RFC 8976). Lives at the
 * zone apex; carries a cryptographic digest of the entire signed
 * zone so a recipient can verify it received the same bytes the
 * publisher committed to. Complements DNSSEC: DNSSEC validates
 * individual RRsets, ZONEMD validates the whole zone as a unit.
 *
 * Wire format:
 *
 * ```
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                          Serial                |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |    Scheme    |  HashAlgo   |                   |
 *  +--+--+--+--+--+--+--+--+--+                     |
 *  /                          Digest                /
 *  /                                                /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * ```
 *
 * - **Serial**: 32-bit zone serial the digest was taken over.
 * - **Scheme**: digest scheme (1 = SIMPLE per RFC 8976 §3).
 * - **HashAlgo**: digest algorithm (1 = SHA-384, 2 = SHA-512).
 * - **Digest**: raw bytes (48 for SHA-384, 64 for SHA-512).
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc8976
 */
export class ZONEMD extends PacketType {

    public serial: number;
    public scheme: number;
    public hashAlgorithm: number;
    public digest: string;

    public constructor(serial: number = 0, scheme: number = 0, hashAlgorithm: number = 0, digest: string = '') {
        super(PacketTypes.ZONEMD);
        this.serial = serial;
        this.scheme = scheme;
        this.hashAlgorithm = hashAlgorithm;
        this.digest = digest;
    }

    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        const digestBuf = Buffer.from(this.digest, 'hex');
        const rdlen = 4 + 1 + 1 + digestBuf.length;

        twriter.write(rdlen, 16);
        twriter.write(this.serial >>> 0, 32);
        twriter.write(this.scheme, 8);
        twriter.write(this.hashAlgorithm, 8);

        for (const byte of digestBuf) {
            twriter.write(byte, 8);
        }

        return twriter.toBuffer();
    }

    public static decode(reader: BufferReader, length: number): PacketType {
        const serial = reader.read(32) >>> 0;
        const scheme = reader.read(8);
        const hashAlgorithm = reader.read(8);

        const digestLen = length - 6;
        const digestBytes: number[] = [];

        for (let i = 0; i < digestLen; i++) {
            digestBytes.push(reader.read(8));
        }

        return new ZONEMD(serial, scheme, hashAlgorithm, Buffer.from(digestBytes).toString('hex'));
    }

}