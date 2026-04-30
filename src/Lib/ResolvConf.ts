import fs from 'fs';

/**
 * Options portion of a `/etc/resolv.conf`. Mirrors the
 * resolver(5)/glibc set; missing keys mean "use the system default"
 * (typically `ndots=1`, `timeout=5`, `attempts=2`). The class lifts
 * everything to optional so callers can `if (opts.ndots !== undefined)`
 * cleanly.
 */
export type ResolvConfOptions = {
    /**
     * Threshold of dots in a query name above which the resolver tries
     * the unmodified name *before* appending search-list suffixes.
     * RFC 3484 / resolver(5) default: 1.
     */
    ndots?: number;

    /**
     * Per-query timeout (seconds) before retrying or moving to the next
     * server. resolver(5) default: 5.
     */
    timeout?: number;

    /**
     * Times each nameserver is queried before giving up.
     * resolver(5) default: 2.
     */
    attempts?: number;

    /**
     * Round-robin across the nameserver list instead of always using
     * the first. resolver(5) flag.
     */
    rotate?: boolean;

    /**
     * Suppress the per-server retry; use a single attempt across all.
     * resolver(5) flag.
     */
    singleRequest?: boolean;

    /**
     * Send A and AAAA queries on the same socket sequentially rather
     * than on separate sockets. resolver(5) flag.
     */
    singleRequestReopen?: boolean;

    /**
     * Allow `inet6` lookups. resolver(5) flag.
     */
    inet6?: boolean;

    /**
     * Disable DNS-Cookie support. resolver(5) flag — `no-tld-query`,
     * `edns0`, `trust-ad`, `no-aaaa`, etc. fall under here.
     */
    edns0?: boolean;
    trustAd?: boolean;
    noAaaa?: boolean;
    noTldQuery?: boolean;

    /**
     * Any unrecognized `key:value` or bare flag is preserved verbatim
     * here so callers don't lose information they might want to
     * surface to a forwarder configuration.
     */
    unknown?: Record<string, string | boolean>;
};

/**
 * Parsed `/etc/resolv.conf`. Returned by `ResolvConf.parse`.
 */
export type ParsedResolvConf = {
    /**
     * Nameserver IPs in declaration order. Both IPv4 and IPv6 are
     * accepted; resolver(5) §6 says a maximum of three are honoured but
     * the parser keeps everything declared — the caller can apply its
     * own cap.
     */
    nameservers: string[];

    /**
     * Search list — domain suffixes appended to short names. resolver(5)
     * §3 allows up to six entries (256-byte total cap). The parser keeps
     * everything declared; capping is the caller's job.
     */
    search: string[];

    /**
     * Legacy single-domain form (resolver(5) §2 — "domain"). When
     * `search` is empty, callers typically fall back to `[domain]`.
     */
    domain?: string;

    /**
     * Sort-list for the legacy `sortlist` directive. Each entry is the
     * exact `addr/netmask` form that appeared in the file (the parser
     * doesn't expand the netmask). Rare but supported for completeness.
     */
    sortlist: string[];

    options: ResolvConfOptions;
};

/**
 * Parser for resolver(5)-format files (`/etc/resolv.conf` and
 * compatible). Provides a string-driven `parse()` for tests and
 * applications that get the content from somewhere other than the
 * filesystem, plus a thin `fromFile()` convenience that reads the
 * standard path.
 *
 * The parser is intentionally tolerant — unknown directives are
 * skipped silently, malformed `key:value` options are kept verbatim
 * in `options.unknown`. resolver(5) servers themselves are tolerant
 * about unrecognized lines, and a parser that fails closed on the
 * first odd entry would be brittle in real deployments.
 *
 * @docs https://man7.org/linux/man-pages/man5/resolv.conf.5.html
 * @docs https://datatracker.ietf.org/doc/html/rfc1535
 */
export class ResolvConf {

    /**
     * Default location of the system file on Linux/BSD. Windows has
     * no equivalent — callers should detect and skip there.
     */
    public static readonly DEFAULT_PATH: string = '/etc/resolv.conf';

    /**
     * Parse the textual content of a resolver(5) file.
     *
     * @param {string} content
     * @return {ParsedResolvConf}
     */
    public static parse(content: string): ParsedResolvConf {
        const out: ParsedResolvConf = {
            nameservers: [],
            search: [],
            sortlist: [],
            options: {}
        };

        for (const rawLine of content.split(/\r?\n/u)) {
            // Strip comments (`#` or `;` start a comment per resolver(5)).
            const stripped = ResolvConf._stripComment(rawLine).trim();

            if (stripped.length === 0) {
                continue;
            }

            const tokens = stripped.split(/\s+/u);
            const directive = tokens[0].toLowerCase();
            const args = tokens.slice(1);

            switch (directive) {
                case 'nameserver':
                    if (args.length > 0) {
                        out.nameservers.push(args[0]);
                    }

                    break;

                case 'search':
                    // Multiple `search` lines: the LAST one wins per
                    // resolver(5) §3 ("search overrides any previous").
                    out.search = args.slice();
                    break;

                case 'domain':
                    if (args.length > 0) {
                        out.domain = args[0];
                    }

                    break;

                case 'sortlist':
                    out.sortlist = args.slice();
                    break;

                case 'options':
                    ResolvConf._mergeOptions(out.options, args);
                    break;

                default:
                    // Silent skip — resolver(5) tolerates unknown lines.
                    break;
            }
        }

        // resolver(5) §3: when both `search` and `domain` appear, the
        // last directive seen wins; we approximate by leaving both
        // populated and letting callers prefer `search`.
        return out;
    }

    /**
     * Read and parse a resolver(5) file from disk. Defaults to
     * `/etc/resolv.conf`. Throws if the file does not exist; callers
     * who want graceful fallback should catch and decide.
     *
     * @param {string} path
     * @return {ParsedResolvConf}
     */
    public static fromFile(path: string = ResolvConf.DEFAULT_PATH): ParsedResolvConf {
        const content = fs.readFileSync(path, 'utf8');
        return ResolvConf.parse(content);
    }

    /**
     * Strip a trailing `#…` or `;…` comment from one line.
     * @param {string} line
     * @return {string}
     * @protected
     */
    protected static _stripComment(line: string): string {
        const hash = line.indexOf('#');
        const semi = line.indexOf(';');
        const candidates = [hash, semi].filter((i) => i >= 0);

        if (candidates.length === 0) {
            return line;
        }

        return line.slice(0, Math.min(...candidates));
    }

    /**
     * Apply a list of `options` tokens onto `target`. Each token is
     * either a bare flag (`rotate`) or a `key:value` pair
     * (`ndots:2`). Unknown tokens land in `options.unknown` so the
     * caller can still surface them.
     * @param {ResolvConfOptions} target
     * @param {string[]} tokens
     * @protected
     */
    protected static _mergeOptions(target: ResolvConfOptions, tokens: string[]): void {
        for (const tok of tokens) {
            const colon = tok.indexOf(':');
            const key = colon === -1 ? tok : tok.slice(0, colon);
            const value = colon === -1 ? '' : tok.slice(colon + 1);

            switch (key) {
                case 'ndots':
                    target.ndots = ResolvConf._parseInt(value, 1);
                    break;

                case 'timeout':
                    target.timeout = ResolvConf._parseInt(value, 5);
                    break;

                case 'attempts':
                    target.attempts = ResolvConf._parseInt(value, 2);
                    break;

                case 'rotate':
                    target.rotate = true;
                    break;

                case 'single-request':
                case 'single_request':
                    target.singleRequest = true;
                    break;

                case 'single-request-reopen':
                case 'single_request_reopen':
                    target.singleRequestReopen = true;
                    break;

                case 'inet6':
                    target.inet6 = true;
                    break;

                case 'edns0':
                    target.edns0 = true;
                    break;

                case 'trust-ad':
                    target.trustAd = true;
                    break;

                case 'no-aaaa':
                    target.noAaaa = true;
                    break;

                case 'no-tld-query':
                    target.noTldQuery = true;
                    break;

                default:
                    if (target.unknown === undefined) {
                        target.unknown = {};
                    }

                    target.unknown[key] = colon === -1 ? true : value;
                    break;
            }
        }
    }

    /**
     * Parse a decimal int with a fallback. Empty / non-numeric input
     * resolves to `fallback` so a malformed `ndots:` doesn't blow up
     * the whole file.
     * @param {string} s
     * @param {number} fallback
     * @return {number}
     * @protected
     */
    protected static _parseInt(s: string, fallback: number): number {
        const n = Number.parseInt(s, 10);
        return Number.isFinite(n) ? n : fallback;
    }

}