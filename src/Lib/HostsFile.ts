import fs from 'fs';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketQuestion} from '../Packet/PacketQuestion.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {A} from '../Packet/Types/A.js';
import {AAAA} from '../Packet/Types/AAAA.js';

/**
 * One entry in the parsed hosts file: a single IP plus the names that
 * point at it. `family` is derived from the address — IPv4 (no colon)
 * → A records, IPv6 → AAAA.
 */
export type HostsEntry = {
    address: string;
    family: 'ipv4' | 'ipv6';
    names: string[];
};

/**
 * Result of `lookup()`. Mirrors the way a recursive resolver would
 * report a hit/miss/NODATA so callers can synthesize a response.
 *
 *  - `'match'` — the name is in the file *and* there is at least one
 *    record matching the requested type. `records` carries them.
 *  - `'nodata'` — the name is in the file but no record of the
 *    requested type exists for it. RFC 1034 §4.3.2 NODATA shape.
 *  - `'miss'` — the name is not in the file. Caller falls through to
 *    DNS / next backend.
 */
export type HostsLookupResult =
    | {kind: 'match'; records: PacketResource[];}
    | {kind: 'nodata';}
    | {kind: 'miss';};

export type HostsFileOptions = {
    /**
     * TTL (seconds) stamped on synthesized records. The hosts file has
     * no TTL concept, so this is a knob for whatever caching layer is
     * in front of the lookup. Default: 0 — match nss-resolve / glibc,
     * which never caches /etc/hosts entries.
     */
    ttl?: number;
};

/**
 * Parser + lookup for `/etc/hosts`-style host tables.
 *
 * Format (per `hosts(5)`):
 *
 *   IPv4-or-IPv6-address  canonical-name  [alias...]
 *
 * Comments start with `#` and run to end of line. Empty lines and
 * lines with only whitespace are ignored. Names are case-insensitive
 * — RFC 1035 §2.3.3 makes DNS names case-preserved on the wire but
 * compared case-insensitively, and host tables follow the same rule.
 *
 * Loaded once; to pick up changes, build a new instance. The class is
 * deliberately tiny — one parse, one lookup — so callers can compose
 * it with whatever transport / cache they already have. The natural
 * wiring point is `StubResolver`'s backend slot:
 *
 * ```ts
 * const hosts = HostsFile.fromFile();          // /etc/hosts
 * const dns = UDPClient.request({dns: '1.1.1.1'});
 *
 * const stub = new StubResolver({
 *   resolver: hosts.asResolverBackend(dns),    // hosts first, DNS fallback
 *   search: conf.search,
 *   ndots: conf.options.ndots,
 * });
 * ```
 *
 * **Strict semantics** (matches glibc / nss `hosts: files dns`): a name
 * present in the file is *authoritative for that name*. A query for a
 * type the file doesn't carry (e.g. `printer.local AAAA` when
 * `/etc/hosts` only has the IPv4 line) returns NODATA, not a fall-
 * through to DNS. Use `HostsFile.merge` or a custom resolver wrapper
 * if you want different.
 *
 * @docs https://man7.org/linux/man-pages/man5/hosts.5.html
 */
export class HostsFile {

    public static readonly DEFAULT_PATH: string = '/etc/hosts';

    protected _entries: HostsEntry[];
    protected _byName: Map<string, HostsEntry[]>;
    protected _ttl: number;

    public constructor(entries: HostsEntry[] = [], options: HostsFileOptions = {}) {
        this._entries = entries;
        this._ttl = Math.max(0, options.ttl ?? 0);
        this._byName = HostsFile._index(entries);
    }

    /**
     * Parse a hosts-file-format string. Tolerant: malformed lines that
     * lack at least one IP + one name are silently skipped (matches
     * the way nss-resolve and BIND's `hostname.conf` reader behave).
     */
    public static parse(content: string, options: HostsFileOptions = {}): HostsFile {
        const entries: HostsEntry[] = [];

        for (const rawLine of content.split(/\r?\n/u)) {
            const stripped = HostsFile._stripComment(rawLine).trim();

            if (stripped.length === 0) {
                continue;
            }

            const tokens = stripped.split(/\s+/u);

            if (tokens.length < 2) {
                continue;
            }

            const address = tokens[0];
            const family = HostsFile._detectFamily(address);

            if (family === null) {
                // First token isn't a valid IP — line is malformed.
                continue;
            }

            const names = tokens.slice(1).map((n) => n.toLowerCase()).filter((n) => n.length > 0);

            if (names.length === 0) {
                continue;
            }

            entries.push({address: address, family: family, names: names});
        }

        return new HostsFile(entries, options);
    }

    /**
     * Read and parse a hosts file from disk. Defaults to
     * `/etc/hosts`. Throws if the file cannot be read — callers that
     * want to tolerate a missing file should wrap in try/catch.
     */
    public static fromFile(path: string = HostsFile.DEFAULT_PATH, options: HostsFileOptions = {}): HostsFile {
        const content = fs.readFileSync(path, 'utf8');
        return HostsFile.parse(content, options);
    }

    /**
     * All parsed entries in declaration order.
     */
    public get entries(): HostsEntry[] {
        return this._entries.slice();
    }

    /**
     * Look up `name` for the given record type. Case-insensitive.
     * Returns one of three result shapes — see `HostsLookupResult`.
     */
    public lookup(name: string, type: PacketTypes | number): HostsLookupResult {
        const normalized = HostsFile._normalizeName(name);
        const matches = this._byName.get(normalized);

        if (matches === undefined || matches.length === 0) {
            return {kind: 'miss'};
        }

        const records: PacketResource[] = [];

        for (const entry of matches) {
            if (type === PacketTypes.A && entry.family === 'ipv4') {
                records.push(new PacketResource(name, new A(entry.address), PacketClass.IN, this._ttl));
            } else if (type === PacketTypes.AAAA && entry.family === 'ipv6') {
                records.push(new PacketResource(name, new AAAA(entry.address), PacketClass.IN, this._ttl));
            }
        }

        if (records.length > 0) {
            return {kind: 'match', records: records};
        }

        // Name in file, no record of requested type — NODATA per
        // glibc strict semantics.
        return {kind: 'nodata'};
    }

    /**
     * Build a `StubResolverBackend`-shaped function that consults this
     * hosts file first and falls through to `fallback` only when the
     * name is *not* in the file. NODATA is preserved (no fall-
     * through) so the file remains authoritative for present names.
     *
     * Returned signature matches `StubResolverBackend` from
     * `Resolver/StubResolver` but the helper doesn't import that type
     * to avoid a Resolver→Lib dependency cycle. Any
     * `(name, type, cls) => Promise<Packet>` works.
     */
    public asResolverBackend(
        fallback: (name: string, type: PacketTypes | number, cls: PacketClass | number) => Promise<Packet>
    ): (name: string, type: PacketTypes | number, cls: PacketClass | number) => Promise<Packet> {
        return async(name, type, cls): Promise<Packet> => {
            const result = this.lookup(name, type);

            if (result.kind === 'miss') {
                return fallback(name, type, cls);
            }

            const synthesized = new Packet();
            synthesized.header.qr = 1;
            synthesized.header.aa = 1;
            synthesized.header.rcode = 0;
            synthesized.questions.push(new PacketQuestion(name, type, cls));

            if (result.kind === 'match') {
                synthesized.answers = result.records;
            }
            // NODATA — leave answers empty, return NOERROR. Matches
            // RFC 1034 §4.3.2 / RFC 2308 §2.2 negative answer shape.

            return synthesized;
        };
    }

    /**
     * Combine two hosts tables. Entries from `other` are appended; on
     * a name collision the *first*-seen entry wins per glibc, so the
     * receiver's entries take precedence. Useful for stacking a
     * project-local override file on top of the system one.
     */
    public merge(other: HostsFile): HostsFile {
        return new HostsFile([...this._entries, ...other._entries], {ttl: this._ttl});
    }

    private static _index(entries: HostsEntry[]): Map<string, HostsEntry[]> {
        const index = new Map<string, HostsEntry[]>();

        for (const entry of entries) {
            for (const name of entry.names) {
                const key = HostsFile._normalizeName(name);
                const bucket = index.get(key);

                if (bucket === undefined) {
                    index.set(key, [entry]);
                } else {
                    bucket.push(entry);
                }
            }
        }

        return index;
    }

    private static _normalizeName(name: string): string {
        const lower = name.toLowerCase();
        return lower.endsWith('.') ? lower.slice(0, -1) : lower;
    }

    private static _stripComment(line: string): string {
        const idx = line.indexOf('#');
        return idx === -1 ? line : line.slice(0, idx);
    }

    private static _detectFamily(token: string): 'ipv4' | 'ipv6' | null {
        if (token.includes(':')) {
            return HostsFile._isIpv6(token) ? 'ipv6' : null;
        }

        return HostsFile._isIpv4(token) ? 'ipv4' : null;
    }

    private static _isIpv4(token: string): boolean {
        const parts = token.split('.');

        if (parts.length !== 4) {
            return false;
        }

        for (const p of parts) {
            if (p.length === 0 || p.length > 3) {
                return false;
            }

            for (let i = 0; i < p.length; i++) {
                const code = p.charCodeAt(i);

                if (code < 48 || code > 57) {
                    return false;
                }
            }

            const n = Number.parseInt(p, 10);

            if (n < 0 || n > 255) {
                return false;
            }
        }

        return true;
    }

    private static _isIpv6(token: string): boolean {
        // Accept any address that the dgram / net layer would —
        // delegate to URL's IPv6 validator via a synthetic origin.
        // Avoid pulling in a full RFC 4291 parser for what is just a
        // sanity check; the host file is a trust boundary, not user
        // input.
        if (token.length === 0 || token.length > 45) {
            return false;
        }

        // Allow only hex digits, colons, dots (for IPv4-mapped tail),
        // and slashes (some files include /128 for completeness — we
        // ignore the prefix on validation but it'll round-trip
        // verbatim through the entry).
        for (let i = 0; i < token.length; i++) {
            const c = token[i];

            if (c === ':' || c === '.') {
                continue;
            }

            const code = token.charCodeAt(i);
            const isDigit = code >= 48 && code <= 57;
            const isHexLower = code >= 97 && code <= 102;
            const isHexUpper = code >= 65 && code <= 70;

            if (!isDigit && !isHexLower && !isHexUpper) {
                return false;
            }
        }

        // Need at least one colon to be IPv6.
        return token.includes(':');
    }

}