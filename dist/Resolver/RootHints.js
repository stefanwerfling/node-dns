import { PacketClass } from '../Packet/PacketClass.js';
import { PacketResource } from '../Packet/PacketResource.js';
import { PacketTypes } from '../Packet/PacketTypes.js';
import { A } from '../Packet/Types/A.js';
import { AAAA } from '../Packet/Types/AAAA.js';
import { NS } from '../Packet/Types/NS.js';
export class RootHints {
    static DEFAULT_TTL_SECONDS = 86_400;
    static DEFAULT = Object.freeze([
        { name: 'a.root-servers.net.', ipv4: '198.41.0.4', ipv6: '2001:503:ba3e::2:30' },
        { name: 'b.root-servers.net.', ipv4: '170.247.170.2', ipv6: '2801:1b8:10::b' },
        { name: 'c.root-servers.net.', ipv4: '192.33.4.12', ipv6: '2001:500:2::c' },
        { name: 'd.root-servers.net.', ipv4: '199.7.91.13', ipv6: '2001:500:2d::d' },
        { name: 'e.root-servers.net.', ipv4: '192.203.230.10', ipv6: '2001:500:a8::e' },
        { name: 'f.root-servers.net.', ipv4: '192.5.5.241', ipv6: '2001:500:2f::f' },
        { name: 'g.root-servers.net.', ipv4: '192.112.36.4', ipv6: '2001:500:12::d0d' },
        { name: 'h.root-servers.net.', ipv4: '198.97.190.53', ipv6: '2001:500:1::53' },
        { name: 'i.root-servers.net.', ipv4: '192.36.148.17', ipv6: '2001:7fe::53' },
        { name: 'j.root-servers.net.', ipv4: '192.58.128.30', ipv6: '2001:503:c27::2:30' },
        { name: 'k.root-servers.net.', ipv4: '193.0.14.129', ipv6: '2001:7fd::1' },
        { name: 'l.root-servers.net.', ipv4: '199.7.83.42', ipv6: '2001:500:9f::42' },
        { name: 'm.root-servers.net.', ipv4: '202.12.27.33', ipv6: '2001:dc3::35' }
    ]);
    static toRecords(servers = RootHints.DEFAULT, ttlSeconds = RootHints.DEFAULT_TTL_SECONDS) {
        const ns = [];
        const glue = [];
        for (const s of servers) {
            ns.push(new PacketResource('.', new NS(s.name), PacketClass.IN, ttlSeconds));
            glue.push(new PacketResource(s.name, new A(s.ipv4), PacketClass.IN, ttlSeconds));
            if (s.ipv6) {
                glue.push(new PacketResource(s.name, new AAAA(s.ipv6), PacketClass.IN, ttlSeconds));
            }
        }
        return { ns: ns, glue: glue };
    }
    static seedCache(cache, servers = RootHints.DEFAULT, ttlSeconds = RootHints.DEFAULT_TTL_SECONDS) {
        const records = RootHints.toRecords(servers, ttlSeconds);
        cache.set('.', PacketTypes.NS, PacketClass.IN, records.ns, ttlSeconds);
        const byKey = new Map();
        for (const r of records.glue) {
            const k = `${r.name.toLowerCase()}|${r.packetType.type}`;
            const bucket = byKey.get(k);
            if (bucket === undefined) {
                byKey.set(k, { name: r.name, type: r.packetType.type, recs: [r] });
            }
            else {
                bucket.recs.push(r);
            }
        }
        for (const bucket of byKey.values()) {
            cache.set(bucket.name, bucket.type, PacketClass.IN, bucket.recs, ttlSeconds);
        }
    }
    static fromNamedRoot(text) {
        const ns = [];
        const v4 = new Map();
        const v6 = new Map();
        for (const rawLine of text.split(/\r?\n/u)) {
            const line = rawLine.replace(/;.*$/u, '').trim();
            if (line === '') {
                continue;
            }
            const fields = line.split(/\s+/u);
            if (fields.length < 3) {
                continue;
            }
            const owner = fields[0];
            const type = fields[fields.length - 2].toUpperCase();
            const value = fields[fields.length - 1];
            if (owner === '.' && type === 'NS') {
                ns.push(RootHints._fqdn(value));
            }
            else if (type === 'A') {
                v4.set(RootHints._fqdn(owner).toLowerCase(), value);
            }
            else if (type === 'AAAA') {
                v6.set(RootHints._fqdn(owner).toLowerCase(), value);
            }
        }
        const servers = [];
        for (const name of ns) {
            const lookup = name.toLowerCase();
            const ipv4 = v4.get(lookup);
            if (ipv4 === undefined) {
                throw new Error(`RootHints.fromNamedRoot: NS ${name} has no A glue`);
            }
            const ipv6 = v6.get(lookup);
            servers.push(ipv6 === undefined ? { name: name, ipv4: ipv4 } : { name: name, ipv4: ipv4, ipv6: ipv6 });
        }
        return servers;
    }
    static _fqdn(name) {
        return name.endsWith('.') ? name : `${name}.`;
    }
}
//# sourceMappingURL=RootHints.js.map