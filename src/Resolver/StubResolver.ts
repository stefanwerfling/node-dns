import type {ParsedResolvConf} from '../Lib/ResolvConf.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {RCODE} from './RecursiveResolver.js';

/**
 * Pluggable backend that resolves one fully-qualified candidate. Any
 * existing transport — `UDPClient.request(...)`, `RecursiveResolver`'s
 * `resolve`, even a custom forwarder — fits this shape with a thin
 * adapter.
 */
export type StubResolverBackend = (
    name: string,
    type: PacketTypes | number,
    cls: PacketClass | number
) => Promise<Packet>;

export type StubResolverOptions = {
    /**
     * Backend resolver. Called once per FQDN candidate produced by the
     * search-path expansion until one returns a non-NXDOMAIN response.
     */
    resolver: StubResolverBackend;

    /**
     * Search list — domain suffixes appended to short names. Apex form
     * (no leading dot, no trailing dot). Order matters: the first match
     * wins. resolver(5) §3 caps this at 6 entries / 256 bytes total but
     * the stub doesn't enforce that — pass already-trimmed lists.
     */
    search?: string[];

    /**
     * Threshold of dots in a query name that flips it from "try search
     * list first" (default for short names) to "try absolute first"
     * (long names). resolver(5) default: 1. Set to 0 to disable
     * search-list expansion entirely.
     */
    ndots?: number;
};

/**
 * Stub resolver that turns a short name into a sequence of FQDN
 * candidates per the resolver(5) / glibc semantics, then walks the
 * sequence until one candidate produces a non-NXDOMAIN response.
 *
 * Composition target: any existing transport. The stub itself does no
 * networking — it just sequences calls to a `resolver` backend you
 * pass in. That keeps the search-path logic orthogonal to the
 * transport (UDP / TCP / DoT / DoH / RecursiveResolver) and
 * trivially testable with a synchronous mock backend.
 *
 * Search rules implemented:
 *
 *   1. Trailing dot — name is fully qualified. Query the absolute
 *      form once; the search list is *not* consulted, even if
 *      NXDOMAIN. Matches glibc and BIND.
 *   2. Dots ≥ ndots — try the absolute name first; on NXDOMAIN,
 *      walk the search list.
 *   3. Dots &lt; ndots — try every `name.<search>` combination in
 *      order; only fall through to the bare absolute name if every
 *      search entry returns NXDOMAIN. (The default `ndots: 1` puts
 *      every dotless single-label name onto this branch.)
 *
 * Fall-through semantics:
 *   - **NXDOMAIN** advances to the next candidate.
 *   - Every other rcode (NOERROR, NOERROR-with-empty-answers / NODATA,
 *     SERVFAIL, REFUSED, …) is returned to the caller verbatim. NODATA
 *     is a definitive answer for the FQDN, not "name doesn't exist";
 *     SERVFAIL means an upstream blew up and silently advancing would
 *     paper over real failures.
 *   - If every candidate returns NXDOMAIN the *last* response is
 *     returned — preserves the negative-caching rcode and SOA the
 *     auth supplied for the longest candidate.
 *
 * @docs resolver(5)
 */
export class StubResolver {

    protected _resolver: StubResolverBackend;
    protected _search: string[];
    protected _ndots: number;

    public constructor(options: StubResolverOptions) {
        if (typeof options.resolver !== 'function') {
            throw new Error('StubResolver: options.resolver is required');
        }

        this._resolver = options.resolver;
        this._search = StubResolver._normalizeSearch(options.search ?? []);
        this._ndots = Math.max(0, options.ndots ?? 1);
    }

    /**
     * Build a stub from a `ResolvConf.parse(...)` / `ResolvConf.fromFile()`
     * result. `domain` falls back to a single-entry search list when
     * `search` is empty (resolver(5) §2 — legacy directive).
     */
    public static fromConfig(
        parsed: ParsedResolvConf,
        resolver: StubResolverBackend
    ): StubResolver {
        const search = parsed.search.length > 0
            ? parsed.search
            : (parsed.domain !== undefined ? [parsed.domain] : []);

        return new StubResolver({
            resolver: resolver,
            search: search,
            ndots: parsed.options.ndots
        });
    }

    /**
     * Return the ordered list of FQDN candidates the stub would try
     * for `name` under the configured `ndots` and search list. Useful
     * for diagnostics, logging, and unit-testing the expansion
     * semantics in isolation from any real backend.
     */
    public expand(name: string): string[] {
        if (name.endsWith('.')) {
            return [name.slice(0, -1)];
        }

        if (this._search.length === 0 || this._ndots === 0) {
            // Either no search list or expansion disabled — only the
            // bare name is tried. ndots:0 is the conventional way to
            // turn off search expansion (matches glibc).
            return [name];
        }

        const dots = StubResolver._countDots(name);

        const withSuffixes = this._search.map((s) => `${name}.${s}`);

        if (dots >= this._ndots) {
            // Long name — try absolute first, then search list.
            return [name, ...withSuffixes];
        }

        // Short name — try search list first, then absolute as a last
        // resort.
        return [...withSuffixes, name];
    }

    /**
     * Resolve `name` per search-path semantics. Returns the first
     * non-NXDOMAIN response, or the last NXDOMAIN if every candidate
     * fails. The returned `Packet` carries the FQDN candidate that
     * produced the answer in `questions[0].name`, exactly as the
     * backend received it.
     */
    public async resolve(
        name: string,
        type: PacketTypes | number,
        cls: PacketClass | number = PacketClass.IN
    ): Promise<Packet> {
        const candidates = this.expand(name);

        if (candidates.length === 0) {
            throw new Error(`StubResolver.resolve: no candidates produced for "${name}"`);
        }

        let lastNxdomain: Packet | null = null;

        for (const candidate of candidates) {
            const response = await this._resolver(candidate, type, cls);

            if (response.header.rcode === RCODE.NXDOMAIN) {
                lastNxdomain = response;
                continue;
            }

            return response;
        }

        // Every candidate said NXDOMAIN — return the last one so the
        // caller still sees the upstream rcode + any negative-caching
        // SOA in the authority section.
        return lastNxdomain!;
    }

    /**
     * The search list this stub will iterate over. Returns a copy.
     */
    public get search(): string[] {
        return this._search.slice();
    }

    /**
     * The ndots threshold currently in effect.
     */
    public get ndots(): number {
        return this._ndots;
    }

    /**
     * Strip trailing dots and lowercase each search entry. resolver(5)
     * accepts both `example.com` and `example.com.`; the stub keeps a
     * canonical form so duplicates collapse and `name.search` joins
     * are predictable.
     */
    protected static _normalizeSearch(list: string[]): string[] {
        const seen = new Set<string>();
        const out: string[] = [];

        for (const raw of list) {
            const stripped = raw.endsWith('.') ? raw.slice(0, -1) : raw;

            if (stripped.length === 0) {
                continue;
            }

            if (!seen.has(stripped)) {
                seen.add(stripped);
                out.push(stripped);
            }
        }

        return out;
    }

    protected static _countDots(name: string): number {
        let count = 0;

        for (let i = 0; i < name.length; i++) {
            if (name[i] === '.') {
                count++;
            }
        }

        return count;
    }

}