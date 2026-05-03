import {Buffer} from 'buffer';
import dgram from 'dgram';
import {BufferWriter} from '../Lib/BufferWriter.js';
import {
    MDNS_CACHE_FLUSH_BIT,
    MDNS_MULTICAST_IPV4,
    MDNS_MULTICAST_IPV6,
    MDNS_PORT,
    MDNS_QU_BIT
} from '../Client/MdnsClient.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';

/**
 * Outcome of `MdnsProbe.claim()`.
 *
 * - `'claimed'` — three probe windows passed without conflict and the
 *   (optional) announce phase ran. The caller now owns the name on the
 *   link and can serve responses for it via `MdnsServer`.
 * - `'conflict'` — another responder asserted the same name with
 *   different records, or won the simultaneous-probe tiebreak. The
 *   caller must rename and probe again.
 */
export type MdnsProbeResult = {
    result: 'claimed' | 'conflict';

    /**
     * When `result === 'conflict'`, this holds the record from the peer
     * that triggered the conflict — useful for logging / metrics. The
     * record's name + type matches one of the tentative records.
     */
    conflictRecord?: PacketResource;

    /**
     * When `result === 'conflict'`, the address of the peer that
     * caused the conflict.
     */
    conflictSource?: {address: string; port: number;};
};

/**
 * Options for `MdnsProbe.claim()`.
 */
export type MdnsProbeOptions = {
    /**
     * Tentative records being claimed. All records MUST share a single
     * owner name — RFC 6762 §8.1 only describes probing for a single
     * name at a time. The records are sent in the AUTHORITY section
     * of every probe query, and re-used as the response payload of the
     * announce phase.
     */
    records: PacketResource[];

    /**
     * Multicast group + port. Defaults: `224.0.0.251:5353` for `'udp4'`,
     * `[ff02::fb]:5353` for `'udp6'`. Tests usually override this with
     * `127.0.0.1` to avoid joining a real multicast group.
     */
    multicastAddr?: string;
    port?: number;
    family?: 'udp4' | 'udp6';
    interfaceAddress?: string;

    /**
     * Local port to bind the probe socket to. Defaults to `port` —
     * RFC 6762 §15 expects source port 5353 in production. Tests pass
     * a different value (or `0` for ephemeral) so a peer dgram socket
     * can occupy the destination port.
     */
    bindPort?: number;

    /**
     * Whether to attempt joining the multicast group on `bind()`. Auto
     * by default — multicast addresses join, unicast addresses (test
     * setups) skip the join.
     */
    joinMulticastGroup?: boolean;

    /**
     * Random initial delay window (RFC 6762 §8.1: "When ready to send
     * its Multicast DNS probe packet(s) the host should first wait for
     * a short random delay time, uniformly distributed in the range
     * 0–250 ms"). Default: 250.
     */
    initialJitterMs?: number;

    /**
     * How long to wait between consecutive probe queries. Default: 250
     * (RFC 6762 §8.1).
     */
    probeIntervalMs?: number;

    /**
     * Number of probe queries to send before declaring the name
     * claimed. Default: 3 (RFC 6762 §8.1). Each is followed by a
     * `probeIntervalMs` listen window. The total claim time is
     * `initialJitterMs + probeAttempts * probeIntervalMs`.
     */
    probeAttempts?: number;

    /**
     * Number of unsolicited announcement responses to send after a
     * successful probe phase. Default: 2 (RFC 6762 §8.3 minimum). Set
     * to `0` to disable announcing — the caller can then drive its own
     * announcement schedule.
     */
    announceAttempts?: number;

    /**
     * Delay between announcement responses. Default: 1000 (RFC 6762
     * §8.3 — at least one second). Ignored when `announceAttempts < 2`.
     */
    announceIntervalMs?: number;

    /**
     * Optional override for the random source. Only the test suite uses
     * this (deterministic jitter / probe-ID). Returns a value in [0, 1).
     */
    random?: () => number;
};

type ResolvedProbeOptions = {
    records: PacketResource[];
    name: string;
    multicastAddr: string;
    port: number;
    bindPort: number;
    family: 'udp4' | 'udp6';
    interfaceAddress?: string;
    joinMulticastGroup: boolean;
    initialJitterMs: number;
    probeIntervalMs: number;
    probeAttempts: number;
    announceAttempts: number;
    announceIntervalMs: number;
    random: () => number;
};

/**
 * RFC 6762 §8 probing + announcing helper for the mDNS responder side.
 *
 * Before a host can claim a name on the link it must verify that no
 * other responder is already using it. The protocol is:
 *
 *   1. Wait a random 0–250 ms (avoid simultaneous-init storms).
 *   2. Multicast a query for the tentative name (type ANY, QU bit
 *      set), with the tentative records in the AUTHORITY section.
 *   3. Listen for 250 ms. If anyone replies with conflicting records
 *      for the same name, abort and rename. If anyone is *also*
 *      probing for the same name, run the lexicographic tiebreak
 *      from §8.2 — losing host renames, winning host keeps probing.
 *   4. Repeat steps 2–3 two more times.
 *   5. Multicast 2+ announcements (responses with the cache-flush bit
 *      set on every record's class) at least 1 s apart.
 *
 * Probing is a one-shot exchange — when this helper resolves, the
 * socket is torn down. Live serving of the now-claimed name is the
 * `MdnsServer`'s job.
 *
 * The helper is stateless: callers that want to claim multiple names
 * call `claim()` multiple times. Callers that want continuous
 * announcement (RFC 6762 §10 — typical for embedded devices that come
 * online after a long sleep) handle that themselves.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc6762#section-8
 */
export class MdnsProbe {

    /**
     * Run the probe / announce dance for `options.records` and resolve
     * with `'claimed'` (we own the name) or `'conflict'` (someone else
     * asserted it / won the tiebreak — caller must rename).
     */
    public static async claim(options: MdnsProbeOptions): Promise<MdnsProbeResult> {
        const resolved = MdnsProbe._resolveOptions(options);
        return MdnsProbe._run(resolved);
    }

    /**
     * Build the canonical-form RDATA bytes used by the §8.2 tiebreak.
     * Type/class/RDATA only — names are excluded per §8.2.1 because the
     * comparison runs after the names are already known to match.
     *
     * Exposed so consumers / tests can reason about tiebreak outcomes
     * without round-tripping through the socket.
     */
    public static canonicalRecordKey(record: PacketResource): Buffer {
        const writer = new BufferWriter();
        // Type (16), class (16) — strip the cache-flush / QU bit so a
        // peer announcing the same record with cache-flush set doesn't
        // sort differently than our pre-flag tentative copy.
        writer.write(record.packetType.type, 16);
        // eslint-disable-next-line no-bitwise
        writer.write(record.class & ~MDNS_CACHE_FLUSH_BIT, 16);

        // RDATA — encode through a fresh writer so name compression
        // can't leak in (our tentative records may not have wire
        // offsets, and incoming records may compress against an
        // unrelated origin).
        const rdataWriter = new BufferWriter();
        const out = record.packetType.encode(record, rdataWriter);
        writer.writeBuffer(out);

        return writer.toBuffer();
    }

    /**
     * Compare two record sets per RFC 6762 §8.2.
     * Returns `1` when `a` is "later" (and therefore wins the
     * tiebreak), `-1` when `b` is later, `0` when they are equal.
     */
    public static compareRecordSets(a: PacketResource[], b: PacketResource[]): number {
        const ka = a.map((r) => MdnsProbe.canonicalRecordKey(r)).sort(Buffer.compare);
        const kb = b.map((r) => MdnsProbe.canonicalRecordKey(r)).sort(Buffer.compare);

        const lim = Math.min(ka.length, kb.length);

        for (let i = 0; i < lim; i++) {
            const cmp = Buffer.compare(ka[i], kb[i]);

            if (cmp !== 0) {
                return cmp > 0 ? 1 : -1;
            }
        }

        if (ka.length === kb.length) {
            return 0;
        }

        return ka.length > kb.length ? 1 : -1;
    }

    private static _resolveOptions(options: MdnsProbeOptions): ResolvedProbeOptions {
        if (!Array.isArray(options.records) || options.records.length === 0) {
            throw new Error('MdnsProbe.claim: at least one tentative record is required');
        }

        const name = options.records[0].name;

        for (const r of options.records) {
            if (r.name !== name) {
                throw new Error(`MdnsProbe.claim: all tentative records must share one owner name (got "${r.name}" and "${name}")`);
            }
        }

        const family: 'udp4' | 'udp6' = options.family ?? 'udp4';
        const multicastAddr = options.multicastAddr
            ?? (family === 'udp6' ? MDNS_MULTICAST_IPV6 : MDNS_MULTICAST_IPV4);

        const port = options.port ?? MDNS_PORT;

        return {
            records: options.records,
            name: name,
            multicastAddr: multicastAddr,
            port: port,
            bindPort: options.bindPort ?? port,
            family: family,
            interfaceAddress: options.interfaceAddress,
            joinMulticastGroup: options.joinMulticastGroup ?? MdnsProbe._isMulticast(multicastAddr),
            initialJitterMs: options.initialJitterMs ?? 250,
            probeIntervalMs: options.probeIntervalMs ?? 250,
            probeAttempts: options.probeAttempts ?? 3,
            announceAttempts: options.announceAttempts ?? 2,
            announceIntervalMs: options.announceIntervalMs ?? 1000,
            random: options.random ?? Math.random
        };
    }

    private static _run(opts: ResolvedProbeOptions): Promise<MdnsProbeResult> {
        return new Promise<MdnsProbeResult>((resolve, reject) => {
            const socket = dgram.createSocket({type: opts.family, reuseAddr: true});

            let settled = false;
            let timer: NodeJS.Timeout | null = null;
            const ourKeys = opts.records.map((r) => MdnsProbe.canonicalRecordKey(r)).sort(Buffer.compare);

            const cleanup = (): void => {
                if (timer !== null) {
                    clearTimeout(timer);
                    timer = null;
                }

                try {
                    socket.close();
                } catch {
                    /* socket may already be closed */
                }
            };

            const finish = (err: Error | null, result?: MdnsProbeResult): void => {
                if (settled) {
                    return;
                }

                settled = true;
                cleanup();

                if (err) {
                    reject(err);
                } else if (result !== undefined) {
                    resolve(result);
                }
            };

            const wait = (ms: number): Promise<void> => new Promise((r) => {
                timer = setTimeout(() => {
                    timer = null;
                    r();
                }, ms);
                timer.unref?.();
            });

            socket.on('error', (err) => finish(err));

            socket.on('message', (msg, rinfo) => {
                if (settled) {
                    return;
                }

                let parsed: Packet;

                try {
                    parsed = Packet.parse(msg);
                } catch {
                    return;
                }

                const conflict = MdnsProbe._classify(parsed, opts, ourKeys);

                if (conflict !== null) {
                    finish(null, {
                        result: 'conflict',
                        conflictRecord: conflict.record,
                        conflictSource: {address: rinfo.address, port: rinfo.port}
                    });
                }
            });

            const startProbe = async(): Promise<void> => {
                try {
                    if (opts.joinMulticastGroup) {
                        try {
                            if (opts.interfaceAddress !== undefined) {
                                socket.addMembership(opts.multicastAddr, opts.interfaceAddress);
                            } else {
                                socket.addMembership(opts.multicastAddr);
                            }
                        } catch {
                            /* tolerated for unicast / test setups */
                        }
                    }

                    // RFC 6762 §8.1 — initial random 0..jitter delay.
                    await wait(Math.floor(opts.random() * opts.initialJitterMs));

                    if (settled) {
                        return;
                    }

                    for (let i = 0; i < opts.probeAttempts && !settled; i++) {
                        await MdnsProbe._sendProbe(socket, opts);

                        if (settled) {
                            return;
                        }

                        await wait(opts.probeIntervalMs);
                    }

                    if (settled) {
                        return;
                    }

                    // Probe phase passed without conflict. Announce.
                    for (let i = 0; i < opts.announceAttempts && !settled; i++) {
                        if (i > 0) {
                            await wait(opts.announceIntervalMs);

                            if (settled) {
                                return;
                            }
                        }

                        await MdnsProbe._sendAnnouncement(socket, opts);
                    }

                    finish(null, {result: 'claimed'});
                } catch (err) {
                    finish(err instanceof Error ? err : new Error(String(err)));
                }
            };

            socket.bind(opts.bindPort, opts.interfaceAddress, () => {
                startProbe();
            });
        });
    }

    /**
     * Inspect an incoming packet and decide whether it constitutes a
     * conflict for our tentative records. Returns the offending record
     * on conflict, or `null` if the packet is irrelevant or — in the
     * simultaneous-probe case — we won the tiebreak.
     *
     * Two conflict shapes per RFC 6762 §8:
     *   - **Response** (qr=1) carrying records for our name with rdata
     *     not in our tentative set → §8.1 conflict.
     *   - **Query** (qr=0) for our name carrying authority records —
     *     another host is also probing. Run §8.2 lexicographic
     *     tiebreak; we lose iff their records sort *later* than ours.
     */
    private static _classify(
        packet: Packet,
        opts: ResolvedProbeOptions,
        ourKeys: Buffer[]
    ): {record: PacketResource;} | null {
        if (packet.header.qr === 1) {
            // Response — check answers (and authorities, since some
            // responders place announcements there) for our name.
            for (const r of [...packet.answers, ...packet.authorities]) {
                if (!MdnsProbe._nameEquals(r.name, opts.name)) {
                    continue;
                }

                const key = MdnsProbe.canonicalRecordKey(r);

                if (!MdnsProbe._keyInSet(key, ourKeys)) {
                    return {record: r};
                }
            }

            return null;
        }

        // Query — only relevant if it asks about our name AND carries
        // authority records (i.e., it's a probe, not a regular query).
        const asksForOurName = packet.questions.some((q) => MdnsProbe._nameEquals(q.name, opts.name));

        if (!asksForOurName) {
            return null;
        }

        const peerAuthForName = packet.authorities.filter((r) => MdnsProbe._nameEquals(r.name, opts.name));

        if (peerAuthForName.length === 0) {
            // Plain query, not a probe — ignore. We are not yet
            // authoritative; a real response can wait until claim
            // succeeds.
            return null;
        }

        const cmp = MdnsProbe.compareRecordSets(opts.records, peerAuthForName);

        if (cmp >= 0) {
            // We are equal or later → we win the tiebreak. Keep
            // probing. (Equal sets mean both hosts somehow assert the
            // exact same records — there is no real conflict and §8.2
            // doesn't require renaming.)
            return null;
        }

        return {record: peerAuthForName[0]};
    }

    /**
     * Build + send one probe query. RFC 6762 §8.1:
     *
     *   - Question: tentative name, type ANY (255), class IN with
     *     QU bit set (request unicast reply, §5.4).
     *   - Authority: every tentative record being claimed.
     *   - ID: 0 (RFC 6762 §18.1 — multicast queries use ID 0).
     */
    private static _sendProbe(socket: dgram.Socket, opts: ResolvedProbeOptions): Promise<void> {
        const probe = new Packet();
        probe.header.id = 0;
        probe.header.qr = 0;
        probe.header.rd = 0;
        // eslint-disable-next-line no-bitwise
        probe.questions.push(new PacketQuestion(opts.name, PacketTypes.ANY, PacketClass.IN | MDNS_QU_BIT));
        probe.authorities = opts.records.slice();

        return MdnsProbe._sendPacket(socket, probe, opts);
    }

    /**
     * Build + send one announcement response. RFC 6762 §10.2 sets the
     * cache-flush bit on every record's class so any cached entries on
     * the segment are replaced atomically when the announcement is
     * received.
     */
    private static _sendAnnouncement(socket: dgram.Socket, opts: ResolvedProbeOptions): Promise<void> {
        const reply = new Packet();
        reply.header.id = 0;
        reply.header.qr = 1;
        reply.header.aa = 1;
        reply.header.rd = 0;

        // Don't mutate the caller's records — copy with cache-flush bit OR'd in.
        reply.answers = opts.records.map((r) => {
            const copy = new PacketResource(
                r.name,
                r.packetType,
                // eslint-disable-next-line no-bitwise
                r.class | MDNS_CACHE_FLUSH_BIT,
                r.ttl
            );
            return copy;
        });

        return MdnsProbe._sendPacket(socket, reply, opts);
    }

    private static _sendPacket(socket: dgram.Socket, packet: Packet, opts: ResolvedProbeOptions): Promise<void> {
        return new Promise((resolve, reject) => {
            socket.send(packet.toBuffer(), opts.port, opts.multicastAddr, (err) => {
                if (err) {
                    reject(err);
                } else {
                    resolve();
                }
            });
        });
    }

    private static _nameEquals(a: string, b: string): boolean {
        return MdnsProbe._normalizeName(a) === MdnsProbe._normalizeName(b);
    }

    private static _normalizeName(s: string): string {
        const lower = s.toLowerCase();

        if (lower.endsWith('.')) {
            return lower.slice(0, -1);
        }

        return lower;
    }

    private static _keyInSet(needle: Buffer, set: Buffer[]): boolean {
        for (const k of set) {
            if (Buffer.compare(needle, k) === 0) {
                return true;
            }
        }

        return false;
    }

    private static _isMulticast(addr: string): boolean {
        if (addr.includes(':')) {
            return addr.toLowerCase().startsWith('ff');
        }

        const firstOctet = Number.parseInt(addr.split('.')[0], 10);
        return firstOctet >= 224 && firstOctet <= 239;
    }

}