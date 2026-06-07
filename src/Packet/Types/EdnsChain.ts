import {BufferReader} from '../../Lib/BufferReader.js';
import {BufferWriter} from '../../Lib/BufferWriter.js';
import {PacketName} from '../PacketName.js';
import {EdnsOption, EdnsOptionCode} from './EdnsECS.js';

/**
 * EDNS(0) CHAIN Query Requests option (RFC 7901).
 *
 * Sent by a validating resolver in a query to tell the upstream
 * authoritative server how much of the DNSSEC chain the client
 * already has cached. The `closestTrustPoint` is the deepest zone
 * (closest to the qname) for which the client already holds a
 * validated DNSKEY RRset; the server bundles every signed RRset
 * between that trust point and the answer into a single response,
 * cutting the multi-round-trip chain-walk down to one query.
 *
 * Wire format (RFC 7901 §3.1):
 *
 * ```
 *  +0 (MSB)                            +1 (LSB)
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     OPTION-CODE = 13 (CHAIN)  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     OPTION-LENGTH              |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  /     Closest Trust Point        /  (DNS name, uncompressed)
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ```
 *
 * The single payload field is a single uncompressed DNS name. An
 * empty option (length 0) signals "the root" — useful when the
 * client has no cached trust point below the root anchor.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc7901
 */
export class EdnsChain implements EdnsOption {

    public ednsCode: number = EdnsOptionCode.CHAIN;
    public closestTrustPoint: string;

    public constructor(closestTrustPoint: string = '') {
        this.closestTrustPoint = closestTrustPoint;
    }

    public static decode(reader: BufferReader, length: number): EdnsChain {
        if (length === 0) {
            return new EdnsChain('');
        }

        const name = PacketName.decode(reader);
        return new EdnsChain(name);
    }

    public encode(writer: BufferWriter): void {
        if (this.closestTrustPoint.length === 0) {
            return;
        }

        // RFC 7901 §3.1 — uncompressed DNS name. PacketName.encode is
        // pointer-compression-aware so we force a fresh writer to
        // suppress any chance of cross-option compression.
        const inner = new BufferWriter();
        PacketName.encode(this.closestTrustPoint, inner);
        writer.writeBuffer(inner);
    }

}