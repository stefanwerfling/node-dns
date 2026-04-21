import {BufferReader} from '../../Lib/BufferReader.js';
import {PacketName} from '../PacketName.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * RRSIG (decode only)
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

    public constructor() {
        super(PacketTypes.RRSIG);
        this.sigType = 0;
        this.algorithm = 0;
        this.labels = 0;
        this.originalTtl = 0;
        this.expiration = '';
        this.inception = '';
        this.keyTag = 0;
        this.signer = '';
        this.signature = '';
    }

    /**
     * Format date for RRSIG
     * @param {number} timestamp
     * @return {string}
     */
    private static _dateForSig(timestamp: number): string {
        // javascript date is from millisecond
        const date = new Date(timestamp * 1000);

        const month = (date.getUTCMonth() + 1).toString().padStart(2, '0');
        const day = date.getUTCDate().toString().padStart(2, '0');
        const hour = date.getUTCHours().toString().padStart(2, '0');
        const minutes = date.getUTCMinutes().toString().padStart(2, '0');
        const seconds = date.getUTCSeconds().toString().padStart(2, '0');

        return `${date.getFullYear()}${month}${day}${hour}${minutes}${seconds}`;
    }

    /**
     * Decode the Buffer to RRSIG Packet
     * @param {BufferReader} reader
     * @param {number} length
     * @return {PacketType}
     */
    public static decode(reader: BufferReader, length: number): PacketType {
        const rrsig = new RRSIG();

        // Calculate max offset in bits
        const maxOffset = reader.getOffset() + (length * 8);

        rrsig.sigType = reader.read(16);
        rrsig.algorithm = reader.read(8);
        rrsig.labels = reader.read(8);
        rrsig.originalTtl = reader.read(32);
        rrsig.expiration = RRSIG._dateForSig(reader.read(32));
        rrsig.inception = RRSIG._dateForSig(reader.read(32));
        rrsig.keyTag = reader.read(16);
        rrsig.signer = PacketName.decode(reader);

        const maxLength = (maxOffset - reader.getOffset()) / 8;
        const signatureBytes: number[] = [];

        while (signatureBytes.length < maxLength) {
            signatureBytes.push(reader.read(8));
        }

        rrsig.signature = Buffer.from(signatureBytes).toString('base64');

        return rrsig;
    }

}