import {PacketClass} from '../Packet/PacketClass.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {AAAA} from '../Packet/Types/AAAA.js';
import {PTR} from '../Packet/Types/PTR.js';
import {SRV} from '../Packet/Types/SRV.js';
import {TXT} from '../Packet/Types/TXT.js';
import {MdnsClient, MdnsClientOptions} from './MdnsClient.js';

/**
 * One discovered service instance.
 *
 * `name` is the full instance name (`Living Room TV._airplay._tcp.local`).
 * The other fields are populated when the matching SRV / TXT / A
 * records are available — either bundled in the additionals of the
 * PTR response (the common DNS-SD shortcut, RFC 6763 §12) or
 * fetched via follow-up queries when missing.
 */
export type ServiceInstance = {
    /**
     * Full DNS-SD instance name —
     * `<instance>.<service>.<protocol>.<domain>`. Use this as the
     * stable identifier across `browse()` calls.
     */
    name: string;

    /**
     * Hostname from the SRV record's target field. Resolves further
     * to one or more `addresses` entries.
     */
    host?: string;

    /**
     * Port from the SRV record.
     */
    port?: number;

    /**
     * SRV priority. RFC 2782 selection criterion.
     */
    priority?: number;

    /**
     * SRV weight. RFC 2782 selection criterion.
     */
    weight?: number;

    /**
     * TXT key/value pairs (RFC 6763 §6). Boolean keys (TXT entries
     * without `=`) map to `true`; values are kept as strings — DNS-SD
     * doesn't standardise typed values.
     */
    txt?: Record<string, string | true>;

    /**
     * Resolved IPv4/IPv6 addresses for the SRV target. Empty when the
     * A/AAAA records weren't bundled in the response and a follow-up
     * resolve was disabled or returned nothing.
     */
    addresses: string[];
};

/**
 * Per-call options for `ServiceDiscovery.browse`.
 */
export type ServiceDiscoveryOptions = {
    /**
     * Service type token, e.g. `_http._tcp` or `_airplay._tcp`. The
     * leading underscore on each label is part of the DNS-SD wire
     * convention (RFC 6763 §4.1) — the helper does *not* prepend it,
     * so callers can pass tokens that already match what's on the
     * wire.
     */
    serviceType: string;

    /**
     * DNS-SD parent domain. Default: `'local'` (mDNS). Pass a unicast
     * domain (e.g. `'example.com'`) to drive DNS-SD over a unicast
     * resolver instead of mDNS — the helper still uses an
     * `MdnsClient` for the wire calls; tests typically point that at
     * a local responder.
     */
    domain?: string;

    /**
     * Wallclock budget for the initial PTR query, forwarded to
     * `MdnsClient.request`'s `timeoutMs`. Default: 1000.
     */
    timeoutMs?: number;

    /**
     * Whether to issue follow-up SRV / TXT / A / AAAA queries when
     * the PTR response doesn't already bundle them in its additionals
     * section. RFC 6763 §12 encourages responders to bundle, but not
     * every device honours that. Default: true.
     */
    resolveMissing?: boolean;

    /**
     * `MdnsClient` configuration overrides — multicast group, port,
     * interface, family, etc. Useful for tests to point at a local
     * responder.
     */
    mdns?: MdnsClientOptions;
};

/**
 * DNS Service Discovery helper (RFC 6763) on top of `MdnsClient`.
 *
 * DNS-SD layers four queries to enumerate services:
 *
 *   1. `PTR  _<service>._<protocol>.<domain>` — list of instance names
 *   2. `SRV  <instance>` — host + port
 *   3. `TXT  <instance>` — key/value metadata
 *   4. `A` / `AAAA` of the SRV target — IP addresses
 *
 * RFC 6763 §12 encourages responders to bundle the SRV + TXT + A/AAAA
 * for each instance into the *additionals* section of the PTR
 * response, so a well-behaved network finishes discovery in one
 * roundtrip. The helper takes that fast path when records are
 * present and only issues follow-up queries for instances whose data
 * is missing.
 *
 * The helper is pure composition over `MdnsClient` — no new I/O.
 * Tests that drive `MdnsClient` against a local 127.0.0.1 responder
 * also drive `ServiceDiscovery` (see `Test/serviceDiscovery.ts` for
 * the pattern).
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc6763
 */
export class ServiceDiscovery {

    /**
     * Discover every instance of `serviceType` reachable on the
     * configured network.
     *
     * @param {ServiceDiscoveryOptions} options
     * @return {Promise<ServiceInstance[]>}
     */
    public static async browse(options: ServiceDiscoveryOptions): Promise<ServiceInstance[]> {
        const domain = options.domain ?? 'local';
        const queryName = `${options.serviceType}.${domain}`;
        const resolveMissing = options.resolveMissing ?? true;

        const mdnsOpts: MdnsClientOptions = {
            ...(options.mdns ?? {}),
            timeoutMs: options.timeoutMs ?? options.mdns?.timeoutMs ?? 1000
        };

        const resolve = MdnsClient.request(mdnsOpts);
        const responses = await resolve(queryName, PacketTypes.PTR);

        // Fold every PTR + SRV + TXT + A/AAAA from every response into
        // the same per-instance bucket. mDNS is many-to-many: the
        // same instance can appear in multiple responder packets.
        const byInstance: Map<string, ServiceInstance> = new Map();
        const cnames: Map<string, string[]> = new Map(); // host → addresses

        for (const r of responses) {
            ServiceDiscovery._foldRecords(r.packet.answers, byInstance, cnames);
            ServiceDiscovery._foldRecords(r.additionals, byInstance, cnames);
        }

        // Apply collected A/AAAA records to instances whose host matches.
        for (const inst of byInstance.values()) {
            if (inst.host !== undefined) {
                const addrs = cnames.get(ServiceDiscovery._normalize(inst.host));

                if (addrs !== undefined) {
                    inst.addresses = Array.from(new Set([...inst.addresses, ...addrs]));
                }
            }
        }

        if (!resolveMissing) {
            return Array.from(byInstance.values());
        }

        // Issue follow-up queries for instances whose SRV/TXT/A
        // didn't come bundled. We do this in parallel — every gap
        // is independent.
        const sub = MdnsClient.request(mdnsOpts);
        const followUps: Promise<void>[] = [];

        for (const inst of byInstance.values()) {
            if (inst.host === undefined || inst.port === undefined) {
                followUps.push(ServiceDiscovery._fillSrv(sub, inst));
            }

            if (inst.txt === undefined) {
                followUps.push(ServiceDiscovery._fillTxt(sub, inst));
            }
        }

        await Promise.all(followUps);

        // Now any instance that learned a host needs its addresses.
        const addrFollowUps: Promise<void>[] = [];

        for (const inst of byInstance.values()) {
            if (inst.host !== undefined && inst.addresses.length === 0) {
                addrFollowUps.push(ServiceDiscovery._fillAddresses(sub, inst));
            }
        }

        await Promise.all(addrFollowUps);

        return Array.from(byInstance.values());
    }

    /**
     * Resolve a single known instance name into a fully-populated
     * `ServiceInstance`. Useful when you already have the instance
     * name from elsewhere (e.g. a configuration file or an earlier
     * `browse()`) and just need its current host/port/txt/addresses.
     *
     * @param {string} instanceName full instance name (`<inst>.<svc>.<proto>.<domain>`)
     * @param {ServiceDiscoveryOptions} options
     * @return {Promise<ServiceInstance>}
     */
    public static async resolveInstance(
        instanceName: string,
        options: Omit<ServiceDiscoveryOptions, 'serviceType' | 'domain'> = {}
    ): Promise<ServiceInstance> {
        const mdnsOpts: MdnsClientOptions = {
            ...(options.mdns ?? {}),
            timeoutMs: options.timeoutMs ?? options.mdns?.timeoutMs ?? 1000
        };

        const inst: ServiceInstance = {name: instanceName, addresses: []};
        const sub = MdnsClient.request(mdnsOpts);

        await Promise.all([
            ServiceDiscovery._fillSrv(sub, inst),
            ServiceDiscovery._fillTxt(sub, inst)
        ]);

        if (inst.host !== undefined && inst.addresses.length === 0) {
            await ServiceDiscovery._fillAddresses(sub, inst);
        }

        return inst;
    }

    /**
     * Pull SRV / TXT / PTR / A / AAAA records out of `records` into
     * the per-instance buckets keyed by full instance name.
     * @protected
     */
    protected static _foldRecords(
        records: PacketResource[],
        byInstance: Map<string, ServiceInstance>,
        cnames: Map<string, string[]>
    ): void {
        for (const rec of records) {
            const t = rec.packetType;

            if (t instanceof PTR) {
                const key = ServiceDiscovery._normalize(t.domain);

                if (!byInstance.has(key)) {
                    byInstance.set(key, {name: t.domain, addresses: []});
                }
            } else if (t instanceof SRV) {
                const key = ServiceDiscovery._normalize(rec.name);
                const inst = byInstance.get(key) ?? {name: rec.name, addresses: []};
                inst.host = t.target;
                inst.port = t.port;
                inst.priority = t.priority;
                inst.weight = t.weight;
                byInstance.set(key, inst);
            } else if (t instanceof TXT) {
                const key = ServiceDiscovery._normalize(rec.name);
                const inst = byInstance.get(key) ?? {name: rec.name, addresses: []};
                inst.txt = ServiceDiscovery._parseTxt(t);
                byInstance.set(key, inst);
            } else if (t instanceof A || t instanceof AAAA) {
                const host = ServiceDiscovery._normalize(rec.name);
                const addr = (t as A | AAAA).address;
                const list = cnames.get(host) ?? [];

                if (!list.includes(addr)) {
                    list.push(addr);
                }

                cnames.set(host, list);
            }
        }
    }

    /**
     * Issue an SRV query for `inst.name` and merge the answer.
     * @protected
     */
    protected static async _fillSrv(
        resolve: ReturnType<typeof MdnsClient.request>,
        inst: ServiceInstance
    ): Promise<void> {
        const responses = await resolve(inst.name, PacketTypes.SRV);

        for (const r of responses) {
            for (const rec of r.packet.answers) {
                if (rec.packetType instanceof SRV
                    && ServiceDiscovery._normalize(rec.name) === ServiceDiscovery._normalize(inst.name)
                ) {
                    inst.host = rec.packetType.target;
                    inst.port = rec.packetType.port;
                    inst.priority = rec.packetType.priority;
                    inst.weight = rec.packetType.weight;
                    return;
                }
            }
        }
    }

    /**
     * Issue a TXT query for `inst.name` and merge the answer.
     * @protected
     */
    protected static async _fillTxt(
        resolve: ReturnType<typeof MdnsClient.request>,
        inst: ServiceInstance
    ): Promise<void> {
        const responses = await resolve(inst.name, PacketTypes.TXT);

        for (const r of responses) {
            for (const rec of r.packet.answers) {
                if (rec.packetType instanceof TXT
                    && ServiceDiscovery._normalize(rec.name) === ServiceDiscovery._normalize(inst.name)
                ) {
                    inst.txt = ServiceDiscovery._parseTxt(rec.packetType);
                    return;
                }
            }
        }
    }

    /**
     * Issue A + AAAA queries for `inst.host` and append every
     * address to `inst.addresses`.
     * @protected
     */
    protected static async _fillAddresses(
        resolve: ReturnType<typeof MdnsClient.request>,
        inst: ServiceInstance
    ): Promise<void> {
        if (inst.host === undefined) {
            return;
        }

        const target = inst.host;
        const merge = (rec: PacketResource): void => {
            if ((rec.packetType instanceof A || rec.packetType instanceof AAAA)
                && ServiceDiscovery._normalize(rec.name) === ServiceDiscovery._normalize(target)) {
                const addr = (rec.packetType as A | AAAA).address;

                if (!inst.addresses.includes(addr)) {
                    inst.addresses.push(addr);
                }
            }
        };

        const [a, aaaa] = await Promise.all([
            resolve(target, PacketTypes.A, PacketClass.IN),
            resolve(target, PacketTypes.AAAA, PacketClass.IN)
        ]);

        for (const r of [...a, ...aaaa]) {
            for (const rec of r.packet.answers) {
                merge(rec);
            }

            for (const rec of r.additionals) {
                merge(rec);
            }
        }
    }

    /**
     * Lower-cased + trailing-dot stripped key for case-insensitive
     * map lookups. DNS names are case-insensitive at the protocol
     * level (RFC 1035 §2.3.3).
     * @protected
     */
    protected static _normalize(name: string): string {
        const stripped = name.endsWith('.') && name.length > 1 ? name.slice(0, -1) : name;
        return stripped.toLowerCase();
    }

    /**
     * Decode a TXT record's character strings into a key/value
     * dictionary per RFC 6763 §6.3.
     *
     * - Bare `"foo"` (no `=`) maps to `foo: true` (boolean key).
     * - `"foo=bar"` maps to `foo: 'bar'`.
     * - The leading character of an empty string entry isn't a key
     *   per RFC 6763 §6.3 — those are skipped.
     * - The first occurrence of a key wins (RFC 6763 §6.4).
     * @protected
     */
    protected static _parseTxt(txt: TXT): Record<string, string | true> {
        const out: Record<string, string | true> = {};
        const data: string[] = Array.isArray(txt.data) ? txt.data : [txt.data];

        for (const entry of data) {
            if (entry.length === 0) {
                continue;
            }

            const eq = entry.indexOf('=');
            const key = eq === -1 ? entry : entry.slice(0, eq);

            if (key.length === 0) {
                continue;
            }

            if (out[key] !== undefined) {
                continue;
            }

            out[key] = eq === -1 ? true : entry.slice(eq + 1);
        }

        return out;
    }

}
