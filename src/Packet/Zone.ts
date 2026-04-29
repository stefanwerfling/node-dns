import {ZoneParseOptions, ZoneParser} from '../Lib/ZoneParser.js';
import {Packet} from './Packet.js';
import {PacketResource} from './PacketResource.js';
import {PacketTypes} from './PacketTypes.js';
import {SOA} from './Types/SOA.js';

/**
 * In-memory DNS zone — the SOA, the records, and the origin under which
 * relative names were resolved. Used to back authoritative answers and
 * to serve AXFR (RFC 5936) zone transfers.
 */
export class Zone {

    /**
     * Origin of this zone (FQDN with trailing dot, e.g. `example.com.`).
     */
    public origin: string;

    /**
     * All records in the zone. The SOA is included exactly once; AXFR
     * serialization re-emits it as the closing record per RFC 5936 §2.2.
     */
    public records: PacketResource[];

    public constructor(origin: string, records: PacketResource[] = []) {
        this.origin = origin.endsWith('.') ? origin : `${origin}.`;
        this.records = records;
    }

    /**
     * Build a `Zone` by parsing a BIND-style master file.
     * @param {string} text raw zone-file content
     * @param {ZoneParseOptions} options
     * @return {Zone}
     */
    public static fromZoneFile(text: string, options: ZoneParseOptions = {}): Zone {
        const parsed = ZoneParser.parse(text, options);
        return new Zone(parsed.origin, parsed.records);
    }

    /**
     * Return the zone's SOA record. Throws if the zone has none — a zone
     * without SOA cannot serve authoritative answers.
     * @return {PacketResource}
     */
    public soa(): PacketResource {
        const soa = this.records.find((r) => r.packetType.type === PacketTypes.SOA);

        if (!soa) {
            throw new Error('zone has no SOA record');
        }

        return soa;
    }

    /**
     * Iterate records of a given type. Convenience for handlers that need
     * to look up RRsets without writing the filter inline.
     */
    public *recordsOfType(type: PacketTypes): IterableIterator<PacketResource> {
        for (const r of this.records) {
            if (r.packetType.type === type) {
                yield r;
            }
        }
    }

    /**
     * Hard upper bound on the encoded size of one AXFR response message.
     * RFC 1035 §4.2.2 frames TCP DNS messages with a 16-bit length prefix,
     * so a single message cannot exceed 65535 octets on the wire.
     */
    public static readonly AXFR_MAX_MESSAGE_SIZE: number = 65535;

    /**
     * Build the AXFR response messages for the given query.
     *
     * Per RFC 5936 §2.2: the answer section of the response sequence starts
     * with the zone's SOA, lists every other record, and ends with the same
     * SOA again. When the full response fits in one message it is returned
     * as a single-element array (the AxfrClient and most resolvers handle
     * either shape transparently). For larger zones the records are split
     * across multiple messages, each individually under
     * `options.maxMessageSize` (default 65535).
     *
     * Splitting is greedy: records are appended to the current message and
     * the encoded length is rechecked after each push; once the budget is
     * hit, the offending record is rolled back and a fresh message starts.
     * Each message carries the same QID, the original question, and `aa=1`.
     * Throws if a single record cannot fit in any message of the requested
     * size — that signals a malformed zone, not a splittable case.
     *
     * @param {Packet} query the parsed AXFR query (QTYPE=AXFR)
     * @param {{maxMessageSize?: number}} options optional max bytes per
     *        message; defaults to 65535. Lower values force splitting and
     *        are useful for tests.
     * @return {Packet[]}
     */
    public toAxfrPackets(
        query: Packet,
        options: {maxMessageSize?: number;} = {}
    ): Packet[] {
        const maxSize = options.maxMessageSize ?? Zone.AXFR_MAX_MESSAGE_SIZE;
        const soa = this.soa();
        const middle = this.records.filter((r) => r !== soa);
        const allAnswers: PacketResource[] = [soa, ...middle, soa];

        // Fast path: when the whole response fits in one message we keep
        // emitting the original single-packet shape — this is the common
        // case and avoids any per-record encoding overhead.
        const single = Zone._buildAxfrResponse(query);
        single.answers = allAnswers;

        if (single.toBuffer().length <= maxSize) {
            return [single];
        }

        const packets: Packet[] = [];
        let i = 0;

        while (i < allAnswers.length) {
            const pkt = Zone._buildAxfrResponse(query);
            let added = 0;

            while (i < allAnswers.length) {
                pkt.answers.push(allAnswers[i]);

                if (pkt.toBuffer().length > maxSize) {
                    if (added === 0) {
                        throw new Error(
                            `AXFR record at index ${i} does not fit in a ${maxSize}-byte message`
                        );
                    }

                    pkt.answers.pop();
                    break;
                }

                i++;
                added++;
            }

            packets.push(pkt);
        }

        return packets;
    }

    /**
     * Build a fresh response Packet for one frame of an AXFR sequence.
     * Uses `new Packet()` rather than `Packet.createResponseFromRequest`
     * because the latter shares the header reference with the query, which
     * is a footgun when several response packets need distinct fields.
     * @protected
     */
    protected static _buildAxfrResponse(query: Packet): Packet {
        const pkt = new Packet();
        pkt.header.id = query.header.id;
        pkt.header.opcode = query.header.opcode;
        pkt.header.rd = query.header.rd;
        pkt.header.qr = 1;
        pkt.header.aa = 1;
        pkt.questions = query.questions.slice();
        return pkt;
    }

    /**
     * Convenience: extract the SOA's RDATA.
     */
    public soaRdata(): SOA {
        return this.soa().packetType as SOA;
    }

    /**
     * Build the IXFR response (RFC 1995) for the given query.
     *
     * Three response shapes are produced depending on what the client asked
     * for and what history was supplied:
     *
     *   1. **No-change** (RFC 1995 §2.1): if `clientSerial` equals the
     *      zone's current serial, reply with a single message whose only
     *      answer is the current SOA.
     *   2. **Incremental**: if `options.history` chains contiguously from
     *      `clientSerial` to the current serial, build the difference
     *      sequences per RFC 1995 §4.
     *   3. **AXFR fallback**: otherwise serve a full AXFR (RFC 1995 §4 §2:
     *      "A server unable to provide an incremental zone transfer should
     *      respond with a full zone transfer.").
     *
     * @param {Packet} query the parsed IXFR query (QTYPE=IXFR with the
     *        client's current SOA in the AUTHORITY section)
     * @param {{history?: ZoneChangeSet[]}} options optional ordered list of
     *        change sets the server has on hand. Each entry's `toSerial`
     *        must equal the next entry's `fromSerial`.
     * @return {Packet[]}
     */
    public toIxfrPackets(query: Packet, options: {history?: ZoneChangeSet[];} = {}): Packet[] {
        const currentSoa = this.soa();
        const currentSerial = (currentSoa.packetType as SOA).serial;
        const clientSerial = Zone._extractClientSerial(query);
        const response = Packet.createResponseFromRequest(query);

        response.questions = query.questions.slice();
        response.header.aa = 1;

        if (clientSerial === null) {
            // No SOA in authority → behave like AXFR fallback per RFC 1995.
            return this.toAxfrPackets(query);
        }

        if (clientSerial === currentSerial) {
            response.answers = [currentSoa];
            return [response];
        }

        const chain = Zone._stitchChain(options.history ?? [], clientSerial, currentSerial);

        if (chain === null) {
            // No usable history → AXFR fallback.
            return this.toAxfrPackets(query);
        }

        const answers: PacketResource[] = [currentSoa];

        for (const cs of chain) {
            answers.push(cs.fromSoa, ...cs.deletions);
            answers.push(cs.toSoa, ...cs.additions);
        }

        answers.push(currentSoa);
        response.answers = answers;
        return [response];
    }

    /**
     * Read the SOA serial from the AUTHORITY section of an IXFR query.
     * Returns `null` if no SOA is present.
     * @protected
     */
    protected static _extractClientSerial(query: Packet): number|null {
        for (const r of query.authorities) {
            if (r.packetType.type === PacketTypes.SOA) {
                return (r.packetType as SOA).serial;
            }
        }

        return null;
    }

    /**
     * Pick the contiguous prefix of `history` that walks `from → … → to`.
     * Returns `null` if no chain covers the gap.
     * @protected
     */
    protected static _stitchChain(history: ZoneChangeSet[], from: number, to: number): ZoneChangeSet[]|null {
        const chain: ZoneChangeSet[] = [];
        let cursor = from;

        while (cursor !== to) {
            const next = history.find((h) => h.fromSerial === cursor);

            if (!next) {
                return null;
            }

            chain.push(next);
            cursor = next.toSerial;
        }

        return chain;
    }

}

/**
 * One incremental change set between two zone serials. Used as input to
 * `Zone.toIxfrPackets` so the server can answer IXFR queries with diffs
 * instead of full transfers.
 *
 * `fromSoa` is the SOA at `fromSerial`; `toSoa` is the SOA at `toSerial`.
 * Both are full `PacketResource` instances so the IXFR encoder can place
 * them in the answer section verbatim.
 */
export type ZoneChangeSet = {
    fromSerial: number;
    toSerial: number;
    fromSoa: PacketResource;
    toSoa: PacketResource;
    deletions: PacketResource[];
    additions: PacketResource[];
};