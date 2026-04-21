import {BufferReader} from '../../Lib/BufferReader.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';
import {SVCB, SvcParams} from './SVCB.js';

/**
 * HTTPS — HTTPS service binding (RFC 9460).
 *
 * Wire format is identical to SVCB; only the type code differs. Use this
 * class for HTTPS-specific service bindings (i.e. the record type Chrome
 * and other browsers query when resolving https:// URLs).
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc9460
 */
export class HTTPS extends SVCB {

    /**
     * Constructor
     * @param {number} priority
     * @param {string} target
     * @param {SvcParams} params
     */
    public constructor(priority: number = 0, target: string = '', params: SvcParams = {}) {
        super(priority, target, params);
        this.type = PacketTypes.HTTPS;
    }

    /**
     * Decode the Buffer into an HTTPS packet.
     * @param {BufferReader} reader
     * @param {number} length
     * @return {PacketType}
     */
    public static decode(reader: BufferReader, length: number): PacketType {
        return HTTPS.decodeInto(reader, length, HTTPS);
    }

}