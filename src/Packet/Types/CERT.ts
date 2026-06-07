import {Buffer} from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * CERT — Storing Certificates in the DNS (RFC 4398). Generic
 * carrier for X.509, OpenPGP, IPKIX, ACPKIX, etc. — the `certType`
 * field tells the consumer how to parse the `certificate` blob.
 *
 * Wire format:
 *
 * ```
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |          CertType         |          KeyTag    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |   Algorithm  |                                 |
 *  +--+--+--+--+--+                                 |
 *  /                       Certificate              /
 *  /                                                /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * ```
 *
 * - **certType** (16-bit): 1=PKIX, 2=SPKI, 3=PGP, 4=IPKIX, 5=ISPKI,
 *   6=IPGP, 7=ACPKIX, 8=IACPKIX, 253=URI, 254=OID (per RFC 4398 §2.1).
 * - **keyTag** (16-bit): DNSSEC-style key tag for cross-referencing
 *   with DNSKEY when the cert wraps a DNSSEC key. 0 when unused.
 * - **algorithm** (8-bit): mirrors DNSSEC algorithm registry; 0 when
 *   the certType doesn't pair with one.
 * - **certificate**: raw cert bytes, encoded as hex internally.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc4398
 */
export class CERT extends PacketType {

    public certType: number;
    public keyTag: number;
    public algorithm: number;
    public certificate: string;

    public constructor(
        certType: number = 0,
        keyTag: number = 0,
        algorithm: number = 0,
        certificate: string = ''
    ) {
        super(PacketTypes.CERT);
        this.certType = certType;
        this.keyTag = keyTag;
        this.algorithm = algorithm;
        this.certificate = certificate;
    }

    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        const certBuf = Buffer.from(this.certificate, 'hex');
        const rdlen = 5 + certBuf.length;

        twriter.write(rdlen, 16);
        twriter.write(this.certType, 16);
        twriter.write(this.keyTag, 16);
        twriter.write(this.algorithm, 8);

        for (const byte of certBuf) {
            twriter.write(byte, 8);
        }

        return twriter.toBuffer();
    }

    public static decode(reader: BufferReader, length: number): PacketType {
        const certType = reader.read(16);
        const keyTag = reader.read(16);
        const algorithm = reader.read(8);

        const certLen = length - 5;
        const certBytes: number[] = [];

        for (let i = 0; i < certLen; i++) {
            certBytes.push(reader.read(8));
        }

        return new CERT(certType, keyTag, algorithm, Buffer.from(certBytes).toString('hex'));
    }

}