import { Buffer } from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketName} from '../PacketName.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * TSIG error codes (subset of RCODE + TSIG-specific codes, RFC 8945 §4.3).
 */
export enum TsigError {
    NOERROR = 0,
    BADSIG = 16,
    BADKEY = 17,
    BADTIME = 18,
    BADTRUNC = 22
}

/**
 * TSIG — Transaction Signature (RFC 8945).
 *
 * Pseudo-record that appears exactly once at the end of the Additional
 * section of a signed message. The RDATA carries the algorithm, timestamp
 * and the HMAC over the wire message + TSIG variables.
 *
 * Owner NAME = key name, CLASS = ANY (255), TTL = 0, TYPE = 250.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc8945
 */
export class TSIG extends PacketType {

    /**
     * Algorithm domain name (e.g. "hmac-sha256.", uncompressed canonical form).
     */
    public algorithm: string;

    /**
     * 48-bit Unix timestamp (seconds since epoch).
     */
    public timeSigned: number;

    /**
     * Allowed clock skew in seconds.
     */
    public fudge: number;

    /**
     * HMAC output. Length depends on the algorithm (32B for sha256, etc.).
     */
    public mac: Buffer;

    /**
     * Original query ID (echoed back by responses).
     */
    public originalId: number;

    /**
     * TSIG error code.
     */
    public error: number;

    /**
     * Opaque "other data" (used for BADTIME responses to report server time).
     */
    public otherData: Buffer;

    /**
     * Constructor
     * @param {string} algorithm
     * @param {number} timeSigned
     * @param {number} fudge
     * @param {Buffer} mac
     * @param {number} originalId
     * @param {number} error
     * @param {Buffer} otherData
     */
    public constructor(
        algorithm: string = 'hmac-sha256.',
        timeSigned: number = 0,
        fudge: number = 300,
        mac: Buffer = Buffer.alloc(0),
        originalId: number = 0,
        error: number = TsigError.NOERROR,
        otherData: Buffer = Buffer.alloc(0)
    ) {
        super(PacketTypes.TSIG);
        this.algorithm = algorithm;
        this.timeSigned = timeSigned;
        this.fudge = fudge;
        this.mac = mac;
        this.originalId = originalId;
        this.error = error;
        this.otherData = otherData;
    }

    /**
     * Split a 48-bit integer into a 16-bit high word and a 32-bit low word.
     * @param {number} value
     * @return {{hi: number; lo: number;}}
     */
    protected static splitUint48(value: number): {hi: number; lo: number;} {
        const divisor = 0x100000000;

        return {
            hi: Math.floor(value / divisor),
            lo: value % divisor
        };
    }

    /**
     * Combine a 16-bit high word and a 32-bit low word into a 48-bit integer.
     * @param {number} hi
     * @param {number} lo
     * @return {number}
     */
    protected static joinUint48(hi: number, lo: number): number {
        return (hi * 0x100000000) + lo;
    }

    /**
     * Encode TSIG RDATA.
     * @param {PacketResource} _resource
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     */
    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;
        const rdataWriter = new BufferWriter();

        PacketName.encode(this.algorithm, rdataWriter);

        const ts = TSIG.splitUint48(this.timeSigned);
        rdataWriter.write(ts.hi, 16);
        rdataWriter.write(ts.lo, 32);

        rdataWriter.write(this.fudge, 16);

        rdataWriter.write(this.mac.length, 16);
        rdataWriter.writeBuffer(this.mac);

        rdataWriter.write(this.originalId, 16);
        rdataWriter.write(this.error, 16);

        rdataWriter.write(this.otherData.length, 16);
        rdataWriter.writeBuffer(this.otherData);

        const rdataBuf = rdataWriter.toBuffer();
        twriter.write(rdataBuf.length, 16);
        twriter.writeBuffer(rdataWriter);

        return twriter.toBuffer();
    }

    /**
     * Decode the Buffer to a TSIG packet.
     * @param {BufferReader} reader
     * @return {PacketType}
     */
    public static decode(reader: BufferReader): PacketType {
        const rawAlgorithm = PacketName.decode(reader);
        // PacketName.decode strips the root-label dot; TSIG algorithm names
        // are written with a trailing dot in IANA/RFC form, so normalize it
        // back so roundtrips match the canonical TsigAlgorithm values.
        const algorithm = rawAlgorithm.endsWith('.') ? rawAlgorithm : `${rawAlgorithm}.`;

        const hi = reader.read(16);
        const lo = reader.read(32);
        const timeSigned = TSIG.joinUint48(hi, lo);

        const fudge = reader.read(16);

        const macSize = reader.read(16);
        const macBytes: number[] = [];

        for (let i = 0; i < macSize; i++) {
            macBytes.push(reader.read(8));
        }

        const originalId = reader.read(16);
        const error = reader.read(16);

        const otherLen = reader.read(16);
        const otherBytes: number[] = [];

        for (let i = 0; i < otherLen; i++) {
            otherBytes.push(reader.read(8));
        }

        return new TSIG(
            algorithm,
            timeSigned,
            fudge,
            Buffer.from(macBytes),
            originalId,
            error,
            Buffer.from(otherBytes)
        );
    }

}