import {BufferReader} from '../../Lib/BufferReader.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';
import {DNSKEY} from './DNSKEY.js';

/**
 * CDNSKEY — Child DNSKEY (RFC 7344).
 *
 * Wire format is identical to DNSKEY; only the type code differs (60
 * vs. 48). Published by the child zone at its apex to signal which
 * DNSKEY(s) the parent should publish a DS record for. RFC 8078 also
 * defines a "delete" sentinel — `flags=0, protocol=3, algorithm=0`
 * with a single zero byte as the public key — that asks the parent
 * to remove all DS RRs.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc7344
 * @docs https://datatracker.ietf.org/doc/html/rfc8078
 */
export class CDNSKEY extends DNSKEY {

    public constructor(
        flags: number = 0,
        protocol: number = 0,
        algorithm: number = 0,
        key: string = ''
    ) {
        super(flags, protocol, algorithm, key);
        this.type = PacketTypes.CDNSKEY;
    }

    public static decode(reader: BufferReader, length: number): PacketType {
        const dnskey = DNSKEY.decode(reader, length) as DNSKEY;
        const cdnskey = new CDNSKEY(dnskey.flags, dnskey.protocol, dnskey.algorithm, dnskey.key);
        cdnskey.keyTag = dnskey.keyTag;
        cdnskey.zoneKey = dnskey.zoneKey;
        cdnskey.zoneSep = dnskey.zoneSep;
        return cdnskey;
    }

}