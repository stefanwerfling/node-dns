import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketName} from '../PacketName.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * SOA
 * @docs https://tools.ietf.org/html/rfc1035#section-3.3.13
 */
export class SOA extends PacketType {

    public primary: string;

    public admin: string;

    public serial: number;

    public refresh: number;

    public retry: number;

    public expiration: number;

    public minimum: number;

    /**
     * constructor
     * @param {string} primary
     * @param {string} admin
     * @param {number} serial
     * @param {number} refresh
     * @param {number} retry
     * @param {number} expiration
     * @param {number} minimum
     */
    public constructor(
        primary: string = '',
        admin: string = '',
        serial: number = 0,
        refresh: number = 0,
        retry: number = 0,
        expiration: number = 0,
        minimum: number = 0
    ) {
        super(PacketTypes.SOA);
        this.primary = primary;
        this.admin = admin;
        this.serial = serial;
        this.refresh = refresh;
        this.retry = retry;
        this.expiration = expiration;
        this.minimum = minimum;
    }

    /**
     * Encode SOA Packet
     * @param {PacketResource} resource
     * @param {BufferWriter|null} writer
     * @return {Buffer}
     */
    public encode(resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        const namePrimary = PacketName.encode(this.primary);
        const nameAdmin = PacketName.encode(this.admin);

        twriter.write(namePrimary.length + nameAdmin.length + ((32 * 5) / 8), 16);
        twriter.writeBuffer(namePrimary);
        twriter.writeBuffer(nameAdmin);
        twriter.write(this.serial, 32);
        twriter.write(this.refresh, 32);
        twriter.write(this.retry, 32);
        twriter.write(this.expiration, 32);
        twriter.write(this.minimum, 32);

        return twriter.toBuffer();
    }

    /**
     * Decode the Buffer to SOA Packet
     * @param {BufferReader} reader
     * @return {PacketType}
     */
    public static decode(reader: BufferReader): PacketType {
        const soa = new SOA();

        soa.primary = PacketName.decode(reader);
        soa.admin = PacketName.decode(reader);
        soa.serial = reader.read(32);
        soa.refresh = reader.read(32);
        soa.retry = reader.read(32);
        soa.expiration = reader.read(32);
        soa.minimum = reader.read(32);

        return soa;
    }

}