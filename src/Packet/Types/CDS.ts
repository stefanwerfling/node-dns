import {BufferReader} from '../../Lib/BufferReader.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';
import {DS} from './DS.js';

/**
 * CDS — Child DS (RFC 7344).
 *
 * Wire format is identical to DS; only the type code differs (59 vs.
 * 43). Published by the child zone at its apex to signal which DS
 * record(s) the parent should pin in its delegation. RFC 8078 also
 * defines a "delete" sentinel — `keyTag=0, algorithm=0, digestType=0,
 * digest="00"` — that asks the parent to remove all DS RRs.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc7344
 * @docs https://datatracker.ietf.org/doc/html/rfc8078
 */
export class CDS extends DS {

    public constructor(
        keyTag: number = 0,
        algorithm: number = 0,
        digestType: number = 0,
        digest: string = ''
    ) {
        super(keyTag, algorithm, digestType, digest);
        this.type = PacketTypes.CDS;
    }

    public static decode(reader: BufferReader, length: number): PacketType {
        const ds = DS.decode(reader, length) as DS;
        return new CDS(ds.keyTag, ds.algorithm, ds.digestType, ds.digest);
    }

}