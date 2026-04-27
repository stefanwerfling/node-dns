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
     * Build the AXFR response messages for the given query.
     *
     * Implements the simplest valid AXFR shape (RFC 5936 §2.2): a single
     * response message whose answer section starts with the zone's SOA,
     * lists every other record, and ends with the same SOA again. Multi-
     * message splitting (for zones whose serialized form would exceed a
     * single 64 KiB message) is not yet implemented; very large zones must
     * be split by the caller for now.
     *
     * @param {Packet} query the parsed AXFR query (QTYPE=AXFR)
     * @return {Packet[]}
     */
    public toAxfrPackets(query: Packet): Packet[] {
        const soa = this.soa();
        const response = Packet.createResponseFromRequest(query);

        response.questions = query.questions.slice();
        response.header.aa = 1;
        response.answers = [soa, ...this.records.filter((r) => r !== soa), soa];

        return [response];
    }

    /**
     * Convenience: extract the SOA's RDATA.
     */
    public soaRdata(): SOA {
        return this.soa().packetType as SOA;
    }

}