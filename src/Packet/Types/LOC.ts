import {Buffer} from 'buffer';
import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketResource} from '../PacketResource.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';

/**
 * LOC — Geographic Location (RFC 1876). Encodes a position on Earth
 * as latitude / longitude / altitude with explicit horizontal and
 * vertical precision plus the diameter of a sphere of equivalent
 * volume.
 *
 * Wire format (16 bytes RDATA):
 *
 * ```
 *  +--+--+--+--+--+--+--+--+
 *  |  VERSION (0)          |
 *  +--+--+--+--+--+--+--+--+
 *  |       SIZE            |
 *  +--+--+--+--+--+--+--+--+
 *  |     HORIZ PRE         |
 *  +--+--+--+--+--+--+--+--+
 *  |      VERT PRE         |
 *  +--+--+--+--+--+--+--+--+
 *  |       LATITUDE        |   (32-bit, ms of arc north of equator + 2^31)
 *  +--+--+--+--+--+--+--+--+
 *  |       LONGITUDE       |   (32-bit, ms of arc east of prime + 2^31)
 *  +--+--+--+--+--+--+--+--+
 *  |       ALTITUDE        |   (32-bit, cm above (sea level − 100,000 m))
 *  +--+--+--+--+--+--+--+--+
 * ```
 *
 * `size` / `horizPre` / `vertPre` use the same packed encoding:
 * upper nibble = mantissa (1..9), lower nibble = exponent (0..9), so
 * the actual value in centimetres is `mantissa * 10^exponent`. The
 * defaults RFC 1876 §3 prescribes are 1m / 10000m / 10m respectively
 * — which translate to `0x12` / `0x16` / `0x13`.
 *
 * This class carries the raw wire-form integers; presentation-form
 * conversion (deg/min/sec/altitude/precision) is left to callers —
 * none of the resolver / server paths need it, and the math fits in
 * a small follow-up if a zone-file consumer ever asks for it.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc1876
 */
export class LOC extends PacketType {

    public version: number;
    public size: number;
    public horizPre: number;
    public vertPre: number;
    public latitude: number;
    public longitude: number;
    public altitude: number;

    public constructor(
        version: number = 0,
        size: number = 0x12,
        horizPre: number = 0x16,
        vertPre: number = 0x13,
        latitude: number = 0,
        longitude: number = 0,
        altitude: number = 0
    ) {
        super(PacketTypes.LOC);
        this.version = version;
        this.size = size;
        this.horizPre = horizPre;
        this.vertPre = vertPre;
        this.latitude = latitude;
        this.longitude = longitude;
        this.altitude = altitude;
    }

    public encode(_resource: PacketResource, writer: BufferWriter|null = null): Buffer {
        const twriter = writer === null ? new BufferWriter() : writer;

        twriter.write(16, 16);
        twriter.write(this.version, 8);
        twriter.write(this.size, 8);
        twriter.write(this.horizPre, 8);
        twriter.write(this.vertPre, 8);
        twriter.write(this.latitude >>> 0, 32);
        twriter.write(this.longitude >>> 0, 32);
        twriter.write(this.altitude >>> 0, 32);

        return twriter.toBuffer();
    }

    public static decode(reader: BufferReader, length: number): PacketType {
        // Forwards-compatible per RFC 1876 §2: unknown VERSION values
        // are valid wire format but the consumer should ignore the
        // record. We capture VERSION as-is so the caller can decide.
        if (length < 16) {
            throw new Error(`LOC: rdlength ${length} too small (need 16)`);
        }

        const version = reader.read(8);
        const size = reader.read(8);
        const horizPre = reader.read(8);
        const vertPre = reader.read(8);
        const latitude = reader.read(32) >>> 0;
        const longitude = reader.read(32) >>> 0;
        const altitude = reader.read(32) >>> 0;

        return new LOC(version, size, horizPre, vertPre, latitude, longitude, altitude);
    }

}