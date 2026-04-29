import {PacketClass} from '../Packet/PacketClass.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {AAAA} from '../Packet/Types/AAAA.js';
import {NS} from '../Packet/Types/NS.js';
import {DnsCache} from './DnsCache.js';

/**
 * One root nameserver entry. Names are fully qualified (trailing dot).
 */
export type RootServer = {
    /**
     * FQDN of the server, e.g. `a.root-servers.net.`.
     */
    name: string;

    /**
     * IPv4 address, dotted-quad. Required — every root server has IPv4.
     */
    ipv4: string;

    /**
     * IPv6 address, RFC 5952 form. Optional in the type because the
     * resolver tolerates a missing v6 entry (some test fixtures only
     * carry v4); in production every IANA root has both.
     */
    ipv6?: string;
};

/**
 * Records derived from a `RootServer[]` ready to be fed into a cache or a
 * priming-query response.
 */
export type RootHintRecords = {
    /**
     * NS records for the root zone (owner name `.`).
     */
    ns: PacketResource[];

    /**
     * A / AAAA glue records — one per server, IPv4 always, IPv6 when
     * present in the source.
     */
    glue: PacketResource[];
};

/**
 * Bundled root-server hints + helpers for priming a recursive resolver.
 *
 * The IANA root zone is served by 13 logical letters `a`-`m`, each
 * implemented as a large anycast cluster. The bundled `DEFAULT` list is
 * kept up-to-date with `https://www.internic.net/zones/named.root`
 * (canonical root-hints file) and changes only when IANA renumbers a
 * root, which is rare (last change: `b.root-servers.net` IPv4 in 2023).
 *
 * For deployments that want to track the upstream file directly, parse
 * a `named.root` text via `RootHints.fromNamedRoot` and pass the result
 * to `RootHints.seedCache`.
 *
 * @docs https://www.iana.org/domains/root/servers
 * @docs https://datatracker.ietf.org/doc/html/rfc8806 — running a local root
 */
export class RootHints {

    /**
     * Default TTL applied when synthesizing records from `RootServer`
     * entries. Real responses observed from the roots are typically
     * 518400 (6 days); this is intentionally lower so a stale fallback
     * list doesn't outlive a real network update for too long.
     */
    public static readonly DEFAULT_TTL_SECONDS: number = 86_400;

    /**
     * IANA root nameservers. Source:
     * https://www.iana.org/domains/root/servers (verify before relying
     * on these for a production recursor — addresses occasionally change).
     */
    public static readonly DEFAULT: ReadonlyArray<RootServer> = Object.freeze([
        {name: 'a.root-servers.net.', ipv4: '198.41.0.4',     ipv6: '2001:503:ba3e::2:30'},
        {name: 'b.root-servers.net.', ipv4: '170.247.170.2',  ipv6: '2801:1b8:10::b'},
        {name: 'c.root-servers.net.', ipv4: '192.33.4.12',    ipv6: '2001:500:2::c'},
        {name: 'd.root-servers.net.', ipv4: '199.7.91.13',    ipv6: '2001:500:2d::d'},
        {name: 'e.root-servers.net.', ipv4: '192.203.230.10', ipv6: '2001:500:a8::e'},
        {name: 'f.root-servers.net.', ipv4: '192.5.5.241',    ipv6: '2001:500:2f::f'},
        {name: 'g.root-servers.net.', ipv4: '192.112.36.4',   ipv6: '2001:500:12::d0d'},
        {name: 'h.root-servers.net.', ipv4: '198.97.190.53',  ipv6: '2001:500:1::53'},
        {name: 'i.root-servers.net.', ipv4: '192.36.148.17',  ipv6: '2001:7fe::53'},
        {name: 'j.root-servers.net.', ipv4: '192.58.128.30',  ipv6: '2001:503:c27::2:30'},
        {name: 'k.root-servers.net.', ipv4: '193.0.14.129',   ipv6: '2001:7fd::1'},
        {name: 'l.root-servers.net.', ipv4: '199.7.83.42',    ipv6: '2001:500:9f::42'},
        {name: 'm.root-servers.net.', ipv4: '202.12.27.33',   ipv6: '2001:dc3::35'}
    ]);

    /**
     * Convert root-server hints into `PacketResource` records suitable
     * for either seeding a `DnsCache` or returning from a server-side
     * priming-query handler.
     *
     * The owner of every NS record is `.` (the root zone). The glue
     * records' owners are the per-server FQDNs.
     *
     * @param {ReadonlyArray<RootServer>} servers
     * @param {number} ttlSeconds
     * @return {RootHintRecords}
     */
    public static toRecords(
        servers: ReadonlyArray<RootServer> = RootHints.DEFAULT,
        ttlSeconds: number = RootHints.DEFAULT_TTL_SECONDS
    ): RootHintRecords {
        const ns: PacketResource[] = [];
        const glue: PacketResource[] = [];

        for (const s of servers) {
            ns.push(new PacketResource('.', new NS(s.name), PacketClass.IN, ttlSeconds));
            glue.push(new PacketResource(s.name, new A(s.ipv4), PacketClass.IN, ttlSeconds));

            if (s.ipv6) {
                glue.push(new PacketResource(s.name, new AAAA(s.ipv6), PacketClass.IN, ttlSeconds));
            }
        }

        return {ns: ns, glue: glue};
    }

    /**
     * Insert root NS + glue records into a `DnsCache`. After this, the
     * resolver can answer any query by starting at the root delegation
     * (`./NS`) and chasing referrals downward.
     *
     * Called during resolver construction or when `RootHints.DEFAULT` is
     * refreshed.
     *
     * @param {DnsCache} cache
     * @param {ReadonlyArray<RootServer>} servers
     * @param {number} ttlSeconds
     */
    public static seedCache(
        cache: DnsCache,
        servers: ReadonlyArray<RootServer> = RootHints.DEFAULT,
        ttlSeconds: number = RootHints.DEFAULT_TTL_SECONDS
    ): void {
        const records = RootHints.toRecords(servers, ttlSeconds);

        cache.set('.', PacketTypes.NS, PacketClass.IN, records.ns, ttlSeconds);

        // Group glue per owner name + type so each (server, A) and
        // (server, AAAA) becomes its own RRset entry.
        const byKey = new Map<string, {name: string; type: number; recs: PacketResource[];}>();

        for (const r of records.glue) {
            const k = `${r.name.toLowerCase()}|${r.packetType.type}`;
            const bucket = byKey.get(k);

            if (bucket === undefined) {
                byKey.set(k, {name: r.name, type: r.packetType.type, recs: [r]});
            } else {
                bucket.recs.push(r);
            }
        }

        for (const bucket of byKey.values()) {
            cache.set(bucket.name, bucket.type, PacketClass.IN, bucket.recs, ttlSeconds);
        }
    }

    /**
     * Parse a BIND-style `named.root` zone-hints file. Recognizes only
     * the subset used by the canonical root-hints file: NS records at
     * the root and A / AAAA glue. Comments and blank lines are skipped.
     *
     * The parser is intentionally narrow — `named.root` is hand-curated
     * and uses a fixed, simple shape. For arbitrary master files use
     * `Lib/ZoneParser` instead.
     *
     * @param {string} text
     * @return {RootServer[]}
     */
    public static fromNamedRoot(text: string): RootServer[] {
        const ns: string[] = [];
        const v4: Map<string, string> = new Map();
        const v6: Map<string, string> = new Map();

        for (const rawLine of text.split(/\r?\n/u)) {
            const line = rawLine.replace(/;.*$/u, '').trim();

            if (line === '') {
                continue;
            }

            const fields = line.split(/\s+/u);

            // Need at least owner, type, value. Optional fields between
            // owner and type (TTL, class) are ignored — we only care
            // about the type and the value.
            if (fields.length < 3) {
                continue;
            }

            const owner = fields[0];
            const type = fields[fields.length - 2].toUpperCase();
            const value = fields[fields.length - 1];

            if (owner === '.' && type === 'NS') {
                ns.push(RootHints._fqdn(value));
            } else if (type === 'A') {
                v4.set(RootHints._fqdn(owner).toLowerCase(), value);
            } else if (type === 'AAAA') {
                v6.set(RootHints._fqdn(owner).toLowerCase(), value);
            }
        }

        const servers: RootServer[] = [];

        for (const name of ns) {
            const lookup = name.toLowerCase();
            const ipv4 = v4.get(lookup);

            if (ipv4 === undefined) {
                throw new Error(`RootHints.fromNamedRoot: NS ${name} has no A glue`);
            }

            const ipv6 = v6.get(lookup);
            servers.push(ipv6 === undefined ? {name: name, ipv4: ipv4} : {name: name, ipv4: ipv4, ipv6: ipv6});
        }

        return servers;
    }

    /**
     * Append a trailing dot if missing — root-hints names are FQDN.
     * @param {string} name
     * @return {string}
     * @protected
     */
    protected static _fqdn(name: string): string {
        return name.endsWith('.') ? name : `${name}.`;
    }

}