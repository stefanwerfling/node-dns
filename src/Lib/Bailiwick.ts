import {Packet} from '../Packet/Packet.js';
import {PacketResource} from '../Packet/PacketResource.js';

/**
 * Bailiwick checks for DNS responses (RFC 5452 §6).
 *
 * A nameserver that's authoritative for `example.com` is allowed to make
 * statements about `example.com` and its descendants; it has no authority
 * to make statements about `bank.com`. A response that contains records
 * outside the responding server's bailiwick is suspicious — historically
 * such "out-of-zone" records have been the vehicle for cache-poisoning
 * attacks (Kaminsky et al.).
 *
 * `Bailiwick.contains(zone, name)` is the membership test;
 * `Bailiwick.filter(packet, zone)` returns a copy of `packet` with all
 * answer/authority/additional records whose owner names fall outside
 * `zone` removed. Use it whenever you forward records from a server you
 * don't fully trust into a cache or onward query path.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc5452#section-6
 */
export class Bailiwick {

    /**
     * Whether the DNS name `name` is in the zone `zone` — i.e. either
     * equals it or is a strict subdomain. Comparison is case-insensitive
     * (DNS names are case-insensitive at the protocol level), trailing
     * dots are normalized away.
     *
     * `Bailiwick.contains('.', anyName)` is always true (the root zone
     * is the universal bailiwick).
     */
    public static contains(zone: string, name: string): boolean {
        const z = Bailiwick._normalize(zone);
        const n = Bailiwick._normalize(name);

        if (z === '') {
            return true;
        }

        if (n === z) {
            return true;
        }

        return n.endsWith(`.${z}`);
    }

    /**
     * Return a copy of `packet` with every answer / authority / additional
     * record whose owner name falls outside `zone` filtered out. The
     * question section is preserved as-is (a stub asks the questions; we
     * trust our own questions). The header is shallow-copied so callers
     * can mutate counts later.
     *
     * Records of the special pseudo-type OPT (EDNS, owner name "") are
     * always kept — EDNS metadata isn't subject to bailiwick rules.
     */
    public static filter(packet: Packet, zone: string): Packet {
        const filtered = new Packet();
        filtered.header = packet.header;
        filtered.questions = packet.questions.slice();
        filtered.answers = Bailiwick._inZone(packet.answers, zone);
        filtered.authorities = Bailiwick._inZone(packet.authorities, zone);
        filtered.additionals = Bailiwick._inZone(packet.additionals, zone);
        return filtered;
    }

    protected static _inZone(records: PacketResource[], zone: string): PacketResource[] {
        return records.filter((r) => {
            // EDNS OPT records have an empty owner name — keep them.
            if (r.name === '') {
                return true;
            }

            return Bailiwick.contains(zone, r.name);
        });
    }

    protected static _normalize(name: string): string {
        if (name === '.') {
            return '';
        }

        const stripped = name.endsWith('.') ? name.slice(0, -1) : name;
        return stripped.toLowerCase();
    }

}