import {Buffer} from 'buffer';
import {Packet} from '../Packet/Packet.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {EDNS} from '../Packet/Types/EDNS.js';
import {EdnsCookie} from '../Packet/Types/EdnsCookie.js';

/**
 * BADCOOKIE extended rcode (RFC 7873 §5.4). Low nibble (7) lands in the
 * DNS header `rcode`; upper 8 bits (1) live in the OPT RR TTL byte 0.
 */
const BADCOOKIE_RCODE: number = 23;
const BADCOOKIE_HEADER_LOW: number = BADCOOKIE_RCODE & 0xF;
// eslint-disable-next-line no-bitwise
const BADCOOKIE_EXT_HI: number = (BADCOOKIE_RCODE >> 4) & 0xFF;

/**
 * Per-upstream cookie state held by `ClientCookieJar`. The client cookie
 * is generated once on first contact with the upstream and stays stable
 * for that endpoint per RFC 7873 §5.1; the server cookie is `null` until
 * the upstream issues one (in a BADCOOKIE reply or alongside a normal
 * answer).
 */
export type ClientCookieEntry = {
    clientCookie: Buffer;
    serverCookie: Buffer | null;
};

/**
 * Client-side cookie store keyed on `${host}:${port}`. Stable client
 * cookie per upstream, learned server cookie from each response.
 *
 * Sized by upstream count, not by query count — DNS clients typically
 * talk to a handful of resolvers, so no eviction policy is needed.
 * Callers that want isolation between unrelated upstreams can hand each
 * client its own jar; callers that want a single cache across multiple
 * clients can share one jar.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc7873
 */
export class ClientCookieJar {

    protected _entries: Map<string, ClientCookieEntry> = new Map();

    /**
     * Compose the jar key from a `(host, port)` pair. Public so callers
     * can prepopulate entries (e.g. from disk-backed state).
     * @param {string} host
     * @param {number} port
     * @return {string}
     */
    public static key(host: string, port: number): string {
        return `${host}:${port}`;
    }

    /**
     * Look up the entry for `(host, port)`, allocating a fresh client
     * cookie on first contact. The returned entry is a live reference —
     * mutating `serverCookie` updates the jar.
     * @param {string} host
     * @param {number} port
     * @return {ClientCookieEntry}
     */
    public getOrCreate(host: string, port: number): ClientCookieEntry {
        const key = ClientCookieJar.key(host, port);
        const existing = this._entries.get(key);

        if (existing) {
            return existing;
        }

        const entry: ClientCookieEntry = {
            clientCookie: EdnsCookie.generateClientCookie(),
            serverCookie: null
        };

        this._entries.set(key, entry);
        return entry;
    }

    /**
     * Look up the entry for `(host, port)` without allocating. Returns
     * `null` if no prior contact has been recorded.
     * @param {string} host
     * @param {number} port
     * @return {ClientCookieEntry|null}
     */
    public peek(host: string, port: number): ClientCookieEntry | null {
        return this._entries.get(ClientCookieJar.key(host, port)) ?? null;
    }

    /**
     * Record a server cookie observed in a response. No-op when
     * `serverCookie` is `null` — the upstream chose not to include one
     * and we keep the prior value.
     * @param {string} host
     * @param {number} port
     * @param {Buffer|null} serverCookie
     */
    public learn(host: string, port: number, serverCookie: Buffer | null): void {
        if (serverCookie === null) {
            return;
        }

        const entry = this.getOrCreate(host, port);
        entry.serverCookie = serverCookie;
    }

    /**
     * Drop the entry for `(host, port)`. Useful when the upstream has
     * rotated its secret and keeps rejecting cookies the jar believes
     * are valid.
     * @param {string} host
     * @param {number} port
     */
    public forget(host: string, port: number): void {
        this._entries.delete(ClientCookieJar.key(host, port));
    }

    /**
     * Drop every entry. Tests / sigterm-style refresh.
     */
    public clear(): void {
        this._entries.clear();
    }

    /**
     * Number of upstreams tracked.
     * @return {number}
     */
    public size(): number {
        return this._entries.size;
    }

    /**
     * Attach the entry's cookie to `query` as an EDNS COOKIE option,
     * adding an OPT RR if none is present yet. Replaces any existing
     * COOKIE option but preserves other EDNS options (ECS, NSID, ...).
     * Allocates a fresh client cookie if the upstream is new.
     *
     * @param {Packet} query
     * @param {string} host
     * @param {number} port
     */
    public attachTo(query: Packet, host: string, port: number): void {
        const entry = this.getOrCreate(host, port);
        const cookieOption = new EdnsCookie(entry.clientCookie, entry.serverCookie ?? undefined);

        const optIdx = query.additionals.findIndex((r) => r.packetType.type === PacketTypes.EDNS);

        if (optIdx === -1) {
            query.additionals.push(EDNS.createResource([cookieOption]));
            return;
        }

        const opt = query.additionals[optIdx].packetType as EDNS;
        const others = opt.rdata.filter((o) => !(o instanceof EdnsCookie));
        opt.rdata = [...others, cookieOption];
    }

    /**
     * Read the server cookie out of `response` (if any) and stash it for
     * the given upstream. Returns the cookie option seen, for callers
     * that want to look at it further (e.g. BADCOOKIE detection).
     *
     * @param {Packet} response
     * @param {string} host
     * @param {number} port
     * @return {EdnsCookie|null}
     */
    public learnFromResponse(response: Packet, host: string, port: number): EdnsCookie | null {
        const cookie = ClientCookieJar.findCookieOption(response);

        if (cookie && cookie.serverCookie) {
            this.learn(host, port, cookie.serverCookie);
        }

        return cookie;
    }

    /**
     * Scan a packet's additionals for the first EDNS COOKIE option.
     * Exposed so tests and BADCOOKIE detection can reuse the walk.
     * @param {Packet} message
     * @return {EdnsCookie|null}
     */
    public static findCookieOption(message: Packet): EdnsCookie | null {
        for (const r of message.additionals) {
            if (r.packetType.type !== PacketTypes.EDNS) {
                continue;
            }

            for (const opt of (r.packetType as EDNS).rdata) {
                if (opt instanceof EdnsCookie) {
                    return opt;
                }
            }
        }

        return null;
    }

    /**
     * Recover the full 12-bit extended RCODE from a response by joining
     * the DNS header rcode (low 4 bits) with the OPT TTL's high byte
     * (upper 8 bits, RFC 6891 §6.1.3). Returns the header rcode when no
     * OPT is present, matching the pre-EDNS interpretation.
     *
     * @param {Packet} response
     * @return {number}
     */
    public static extendedRcode(response: Packet): number {
        const opt = response.additionals.find((r) => r.packetType.type === PacketTypes.EDNS);
        const headerLow = response.header.rcode & 0xF;

        if (!opt) {
            return headerLow;
        }

        // eslint-disable-next-line no-bitwise
        const extHi = (opt.ttl >>> 24) & 0xFF;
        // eslint-disable-next-line no-bitwise
        return (extHi << 4) | headerLow;
    }

    /**
     * Test whether `response` is a BADCOOKIE reply (RFC 7873 §5.4).
     * Used by clients to drive the single-retry path.
     *
     * @param {Packet} response
     * @return {boolean}
     */
    public static isBadCookie(response: Packet): boolean {
        if ((response.header.rcode & 0xF) !== BADCOOKIE_HEADER_LOW) {
            return false;
        }

        const opt = response.additionals.find((r) => r.packetType.type === PacketTypes.EDNS);

        if (!opt) {
            return false;
        }

        // eslint-disable-next-line no-bitwise
        return ((opt.ttl >>> 24) & 0xFF) === BADCOOKIE_EXT_HI;
    }

}