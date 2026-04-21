import { Buffer } from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * DNSKEY
 * @docs https://tools.ietf.org/html/rfc4034
 * @docs https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
 */
export class DNSKEY extends PacketType {

    public flags: number;
    public protocol: number;
    public algorithm: number;
    public keyTag: number;
    public zoneKey: boolean;
    public zoneSep: boolean;
    public key: string;

    public constructor(
        flags: number = 0,
        protocol: number = 0,
        algorithm: number = 0,
        key: string = ''
    ) {
        super(PacketTypes.DNSKEY);
        this.flags = flags;
        this.protocol = protocol;
        this.algorithm = algorithm;
        this.key = key;
        this.keyTag = 0;
        this.zoneKey = false;
        this.zoneSep = false;
    }

    /**
     * Encode DNSKEY Packet
     * @param {PacketResource} _resource
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     */
    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        const keyBuffer = Buffer.from(this.key, 'base64');

        twriter.write(4 + keyBuffer.length, 16);
        twriter.write(this.flags, 16);
        twriter.write(this.protocol, 8);
        twriter.write(this.algorithm, 8);

        for (const c of keyBuffer) {
            twriter.write(c, 8);
        }

        return twriter.toBuffer();
    }

    /**
     * Decode the Buffer to DNSKEY Packet
     * @param {BufferReader} reader
     * @param {number} length
     * @return {PacketType}
     */
    public static decode(reader: BufferReader, length: number): PacketType {
        const rdata: number[] = [];

        while (rdata.length < length) {
            rdata.push(reader.read(8));
        }

        const dnskey = new DNSKEY();

        // eslint-disable-next-line no-bitwise
        dnskey.flags = rdata[0] << 8 | rdata[1];
        dnskey.protocol = rdata[2];
        dnskey.algorithm = rdata[3];

        // Calculate key tag
        let ac = 0;

        for (let i = 0; i < length; ++i) {
            // eslint-disable-next-line no-bitwise
            ac += (i & 1) ? rdata[i] : rdata[i] << 8;
        }

        // eslint-disable-next-line no-bitwise
        ac += (ac >> 16) & 0xFFFF;
        // eslint-disable-next-line no-bitwise
        dnskey.keyTag = ac & 0xFFFF;

        // Convert binary flags
        let binFlags = dnskey.flags.toString(2);

        while (binFlags.length < 16) {
            binFlags = `0${binFlags}`;
        }

        dnskey.zoneKey = binFlags[7] === '1';
        dnskey.zoneSep = binFlags[15] === '1';
        dnskey.key = Buffer.from(rdata.slice(4)).toString('base64');

        return dnskey;
    }

}