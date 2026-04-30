import dgram from 'dgram';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';

/**
 * IPv4 multicast address for mDNS — RFC 6762 §3.
 */
export const MDNS_MULTICAST_IPV4: '224.0.0.251' = '224.0.0.251';

/**
 * IPv6 multicast address for mDNS — RFC 6762 §3.
 */
export const MDNS_MULTICAST_IPV6: 'ff02::fb' = 'ff02::fb';

/**
 * mDNS port — RFC 6762 §3.
 */
export const MDNS_PORT: 5353 = 5353;

/**
 * QU (Query Unicast) bit. Top bit of QCLASS in a question RR
 * (RFC 6762 §5.4) — when set, the responder is asked to reply
 * unicast to the source port instead of multicasting.
 */
export const MDNS_QU_BIT: 0x8000 = 0x8000;

/**
 * Cache-flush bit. Top bit of CLASS in an answer RR (RFC 6762 §10.2)
 * — when set, the responder is announcing that this RRset replaces
 * any previously cached records for the same name/type.
 */
export const MDNS_CACHE_FLUSH_BIT: 0x8000 = 0x8000;

/**
 * Per-call options for `MdnsClient.request`.
 */
export type MdnsClientOptions = {
    /**
     * Multicast group to send the query to. Default
     * `224.0.0.251` for `'udp4'`, `ff02::fb` for `'udp6'`. May be
     * overridden with a unicast address in tests / DNSDR setups
     * where no multicast group is available.
     */
    multicastAddr?: string;

    /**
     * UDP port queried. RFC 6762 §3 fixes this at 5353.
     */
    port?: number;

    /**
     * Wallclock budget (ms) — the client listens for responses for
     * this long, then resolves with everything collected. mDNS is a
     * one-to-many protocol, so multiple devices may reply: there is
     * no "first response wins" pattern. Default: 1000.
     */
    timeoutMs?: number;

    /**
     * Address family. Default: `'udp4'`.
     */
    family?: 'udp4' | 'udp6';

    /**
     * Set the QU bit (RFC 6762 §5.4) on the outgoing question — ask
     * the responder to reply via unicast to our source port instead
     * of multicast. Useful for one-shot lookups where you don't want
     * every other device on the segment to see the answer (and the
     * cache-population side-effect that comes with multicast).
     * Default: false.
     */
    unicastResponse?: boolean;

    /**
     * Local interface address to bind the socket to. Default: let
     * the OS pick. Mostly useful on hosts with multiple interfaces
     * where you need to scope the multicast to a specific link.
     */
    interfaceAddress?: string;

    /**
     * Whether to attempt joining the multicast group on `bind()`. The
     * implementation tolerates failure (e.g. when the address is
     * unicast for testing), but you can suppress the attempt
     * entirely. Default: true when `multicastAddr` is in the
     * multicast range (224.0.0.0/4 or ff00::/8), false otherwise.
     */
    joinMulticastGroup?: boolean;
};

/**
 * One response from one responder. mDNS is many-to-many, so a single
 * query can produce zero, one, or many of these.
 */
export type MdnsResponse = {
    /**
     * The full parsed response packet — convenient for callers that
     * want headers/authorities, not just the answer + additionals.
     */
    packet: Packet;

    /**
     * Records in the answer section.
     */
    answers: PacketResource[];

    /**
     * Records in the additionals section. Service-discovery responses
     * pile useful records here (PTR target's SRV+TXT+A/AAAA in one
     * exchange).
     */
    additionals: PacketResource[];

    /**
     * IP + port of the responder. The port may not be 5353 when the
     * responder used unicast reply.
     */
    sender: {
        address: string;
        port: number;
    };
};

/**
 * Multicast DNS client (RFC 6762).
 *
 * mDNS is the protocol behind `.local` host names and Bonjour /
 * service discovery. Functionally the wire format is identical to
 * unicast DNS, but the framing and semantics differ:
 *
 *  - Queries go to the link-local multicast group (224.0.0.251 IPv4
 *    / ff02::fb IPv6) on UDP port 5353.
 *  - Responses are also (typically) multicast — every device on the
 *    segment listens, so a single query can collect responses from
 *    many devices. The QU bit (top bit of QCLASS, RFC 6762 §5.4)
 *    asks for a unicast reply instead.
 *  - There is no fixed transaction ID — RFC 6762 §18.1 says
 *    requesters MUST set the ID to 0 in unsolicited multicast
 *    queries; we do.
 *  - TTL conventions differ — see RFC 6762 §10. Caching is the
 *    application's job; this client just collects responses.
 *
 * The implementation is intentionally minimal: send one query, listen
 * for `timeoutMs`, return the aggregated responses. Service-discovery
 * (RFC 6763 / DNS-SD) sits on top of this — a caller composes PTR /
 * SRV / TXT / A queries to enumerate `_http._tcp.local`-style
 * services.
 *
 * Tests can use a unicast address (`127.0.0.1`) instead of the real
 * multicast group: the multicast-group join is wrapped in
 * `try/catch` and silently skipped on a unicast target, so the
 * client behaves like a regular UDP client over loopback.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc6762
 */
export class MdnsClient {

    /**
     * Build a query packet shaped for mDNS.
     *
     * @param {string} name
     * @param {PacketTypes|number} type
     * @param {PacketClass|number} cls
     * @param {boolean} unicastResponse set the QU bit on the question
     * @return {Packet}
     */
    public static makeQuery(
        name: string,
        type: PacketTypes | number,
        cls: PacketClass | number = PacketClass.IN,
        unicastResponse: boolean = false
    ): Packet {
        const packet = new Packet();
        // RFC 6762 §18.1 — unsolicited multicast queries use ID=0.
        packet.header.id = 0;
        packet.header.rd = 0;

        // eslint-disable-next-line no-bitwise
        const effectiveClass = unicastResponse ? cls | MDNS_QU_BIT : cls;

        packet.questions.push(new PacketQuestion(name, type, effectiveClass));
        return packet;
    }

    /**
     * Build a resolver function. Each call sends one query and
     * collects every response that arrives within `timeoutMs`.
     *
     * @param {MdnsClientOptions} options
     * @return {(name: string, type: PacketTypes|number, cls?: PacketClass|number) => Promise<MdnsResponse[]>}
     */
    public static request(options: MdnsClientOptions = {}): (
        name: string,
        type: PacketTypes | number,
        cls?: PacketClass | number
    ) => Promise<MdnsResponse[]> {
        const family: 'udp4' | 'udp6' = options.family ?? 'udp4';
        const multicastAddr = options.multicastAddr
            ?? (family === 'udp6' ? MDNS_MULTICAST_IPV6 : MDNS_MULTICAST_IPV4);
        const port = options.port ?? MDNS_PORT;
        const timeoutMs = options.timeoutMs ?? 1000;
        const joinGroup = options.joinMulticastGroup
            ?? MdnsClient._isMulticast(multicastAddr);

        return (
            name: string,
            type: PacketTypes | number,
            cls: PacketClass | number = PacketClass.IN
        ): Promise<MdnsResponse[]> => {
            return new Promise((resolve, reject) => {
                const socket = dgram.createSocket({type: family, reuseAddr: true});
                const responses: MdnsResponse[] = [];
                let settled = false;
                let timer: NodeJS.Timeout | null = null;

                const finish = (err: Error | null): void => {
                    if (settled) {
                        return;
                    }

                    settled = true;

                    if (timer !== null) {
                        clearTimeout(timer);
                    }

                    try {
                        socket.close();
                    } catch {
                        /* socket may already be closed */
                    }

                    if (err) {
                        reject(err);
                    } else {
                        resolve(responses);
                    }
                };

                socket.on('error', (err) => finish(err));

                socket.on('message', (msg, rinfo) => {
                    let parsed: Packet;

                    try {
                        parsed = Packet.parse(msg);
                    } catch {
                        // Bogus message — ignore. mDNS shares the
                        // multicast group with everyone, including
                        // misbehaved devices.
                        return;
                    }

                    // Only collect responses (QR=1). Our own query
                    // bounces back when reuseAddr is on.
                    if (parsed.header.qr !== 1) {
                        return;
                    }

                    responses.push({
                        packet: parsed,
                        answers: parsed.answers,
                        additionals: parsed.additionals,
                        sender: {address: rinfo.address, port: rinfo.port}
                    });
                });

                const startQuery = (): void => {
                    if (joinGroup) {
                        try {
                            if (options.interfaceAddress !== undefined) {
                                socket.addMembership(multicastAddr, options.interfaceAddress);
                            } else {
                                socket.addMembership(multicastAddr);
                            }
                        } catch {
                            // Joining can fail in test / non-multicast
                            // environments; the send still goes through.
                        }
                    }

                    const query = MdnsClient.makeQuery(name, type, cls, options.unicastResponse);

                    socket.send(query.toBuffer(), port, multicastAddr, (err) => {
                        if (err) {
                            finish(err);
                            return;
                        }

                        timer = setTimeout(() => finish(null), timeoutMs);
                        timer.unref?.();
                    });
                };

                socket.bind(0, options.interfaceAddress, startQuery);
            });
        };
    }

    /**
     * Whether `addr` is in the IPv4 (224.0.0.0/4) or IPv6 (ff00::/8)
     * multicast range. Used to decide whether to attempt
     * `addMembership` automatically.
     * @param {string} addr
     * @return {boolean}
     * @protected
     */
    protected static _isMulticast(addr: string): boolean {
        if (addr.includes(':')) {
            // IPv6 multicast: ff00::/8.
            return addr.toLowerCase().startsWith('ff');
        }

        // IPv4 multicast: 224.0.0.0–239.255.255.255.
        const firstOctet = Number.parseInt(addr.split('.')[0], 10);
        return firstOctet >= 224 && firstOctet <= 239;
    }

}