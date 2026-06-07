import {BufferReader} from '../../Lib/BufferReader.js';
import {PacketType} from '../PacketType.js';
import {PacketTypes} from '../PacketTypes.js';
import {TLSA} from './TLSA.js';

/**
 * SMIMEA — S/MIME Certificate Association (RFC 8162).
 *
 * Wire format is identical to TLSA; only the type code differs (53
 * vs. 52). Owner name convention per RFC 8162 §3 is `<sha256(local-
 * part)[0..56]>._smimecert.<domain>` — analogous to OPENPGPKEY's
 * `_openpgpkey` label.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc8162
 */
export class SMIMEA extends TLSA {

    public constructor(
        usage: number = 0,
        selector: number = 0,
        matchingType: number = 0,
        certificate: string = ''
    ) {
        super(usage, selector, matchingType, certificate);
        this.type = PacketTypes.SMIMEA;
    }

    public static decode(reader: BufferReader, length: number): PacketType {
        const tlsa = TLSA.decode(reader, length) as TLSA;
        return new SMIMEA(tlsa.usage, tlsa.selector, tlsa.matchingType, tlsa.certificate);
    }

}