import { Buffer } from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketName} from '../PacketName.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * RRSIG
 * @docs https://tools.ietf.org/html/rfc4034
 */
export class RRSIG extends PacketType {

    public sigType: number;
    public algorithm: number;
    public labels: number;
    public originalTtl: number;
    public expiration: string;
    public inception: string;
    public keyTag: number;
    public signer: string;
    public signature: string;

    public constructor(
        sigType: number = 0,
        algorithm: number = 0,
        labels: number = 0,
        originalTtl: number = 0,
        expiration: string = '',
        inception: string = '',
        keyTag: number = 0,
        signer: string = '',
        signature: string = ''
    ) {
        super(PacketTypes.RRSIG);
        this.sigType = sigType;
        this.algorithm = algorithm;
        this.labels = labels;
        this.originalTtl = originalTtl;
        this.expiration = expiration;
        this.inception = inception;
        this.keyTag = keyTag;
        this.signer = signer;
        this.signature = signature;
    }

    /**
     * Format unix timestamp as RFC 4034 §3.2 YYYYMMDDHHMMSS in UTC.
     * @param {number} timestamp
     * @return {string}
     */
    private static _dateForSig(timestamp: number): string {
        const date = new Date(timestamp * 1000);

        const year = date.getUTCFullYear().toString().padStart(4, '0');
        const month = (date.getUTCMonth() + 1).toString().padStart(2, '0');
        const day = date.getUTCDate().toString().padStart(2, '0');
        const hour = date.getUTCHours().toString().padStart(2, '0');
        const minutes = date.getUTCMinutes().toString().padStart(2, '0');
        const seconds = date.getUTCSeconds().toString().padStart(2, '0');

        return `${year}${month}${day}${hour}${minutes}${seconds}`;
    }

    /**
     * Parse a presentation-form date back into the uint32 wire value.
     * Accepts either a plain unsigned decimal integer (raw seconds) or the
     * RFC 4034 §3.2 `YYYYMMDDHHMMSS` form interpreted in UTC.
     * @param {string} value
     * @return {number}
     */
    private static _parseSigDate(value: string): number {
        if (/^\d+$/.test(value) && value.length !== 14) {
            return parseInt(value, 10);
        }

        if (!/^\d{14}$/.test(value)) {
            throw new Error(`RRSIG: invalid date "${value}"`);
        }

        const year = parseInt(value.slice(0, 4), 10);
        const month = parseInt(value.slice(4, 6), 10);
        const day = parseInt(value.slice(6, 8), 10);
        const hour = parseInt(value.slice(8, 10), 10);
        const minute = parseInt(value.slice(10, 12), 10);
        const second = parseInt(value.slice(12, 14), 10);

        return Math.floor(Date.UTC(year, month - 1, day, hour, minute, second) / 1000);
    }

    /**
     * Encode RRSIG. RFC 6840 §5.1 forbids name compression for DNSSEC RR
     * types — the rdata is built in a fresh writer so the signer name is
     * always emitted as labels + null.
     */
    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        const rdataWriter = new BufferWriter();
        rdataWriter.write(this.sigType, 16);
        rdataWriter.write(this.algorithm, 8);
        rdataWriter.write(this.labels, 8);
        rdataWriter.write(this.originalTtl, 32);
        rdataWriter.write(RRSIG._parseSigDate(this.expiration), 32);
        rdataWriter.write(RRSIG._parseSigDate(this.inception), 32);
        rdataWriter.write(this.keyTag, 16);
        PacketName.encode(this.signer, rdataWriter);

        const sigBuf = Buffer.from(this.signature, 'base64');
        rdataWriter.writeBuffer(sigBuf);

        const rdataBuf = rdataWriter.toBuffer();
        twriter.write(rdataBuf.length, 16);
        twriter.writeBuffer(rdataBuf);

        return twriter.toBuffer();
    }

    /**
     * Decode the Buffer to RRSIG Packet
     * @param {BufferReader} reader
     * @param {number} length
     * @return {PacketType}
     */
    public static decode(reader: BufferReader, length: number): PacketType {
        const maxOffset = reader.getOffset() + (length * 8);

        const sigType = reader.read(16);
        const algorithm = reader.read(8);
        const labels = reader.read(8);
        const originalTtl = reader.read(32);
        const expiration = RRSIG._dateForSig(reader.read(32));
        const inception = RRSIG._dateForSig(reader.read(32));
        const keyTag = reader.read(16);
        const signer = PacketName.decode(reader);

        const sigByteLen = (maxOffset - reader.getOffset()) / 8;
        const signatureBytes: number[] = [];

        while (signatureBytes.length < sigByteLen) {
            signatureBytes.push(reader.read(8));
        }

        const signature = Buffer.from(signatureBytes).toString('base64');

        return new RRSIG(sigType, algorithm, labels, originalTtl, expiration, inception, keyTag, signer, signature);
    }

}