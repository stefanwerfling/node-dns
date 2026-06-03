import fs from 'fs';
import {HostsFile} from '../Lib/HostsFile.js';
import {ParsedResolvConf, ResolvConf} from '../Lib/ResolvConf.js';
import {UDPClient} from '../Client/UDPClient.js';
import {Packet} from '../Packet/Packet.js';
import {PacketClass} from '../Packet/PacketClass.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {CachedStubBackend} from './CachedStubBackend.js';
import {DnsCache, DnsCacheOptions} from './DnsCache.js';
import {FailoverBackend, FailoverBackendBuilder, FailoverPredicate} from './FailoverBackend.js';
import {StubResolver, StubResolverBackend} from './StubResolver.js';

/**
 * Cache configuration:
 *
 *   - `false` / omitted — no cache (the default; matches a typical
 *     stub resolver that just forwards every query).
 *   - `true` — wrap the upstream with a `CachedStubBackend` using
 *     `DnsCache` defaults (10k entries, 1-day max TTL, RFC 2308
 *     negative caching).
 *   - `DnsCache` instance — share an external cache across multiple
 *     `SystemResolver`s, or pre-populate it.
 *   - `DnsCacheOptions` object — build a fresh `DnsCache` with the
 *     given knobs (`maxEntries`, `min/maxTtlSeconds`,
 *     `maxStaleSeconds` for RFC 8767, `prefetchThreshold`, …).
 */
export type SystemResolverCache = boolean | DnsCache | DnsCacheOptions;

export type SystemResolverOptions = {
    /**
     * Path to the resolver(5) file. Default `/etc/resolv.conf`.
     */
    resolvConfPath?: string;

    /**
     * Path to the hosts(5) file. Default `/etc/hosts`. Silently
     * skipped when the file is missing — this matches glibc, which
     * tolerates a missing `/etc/hosts` and proceeds with DNS only.
     */
    hostsPath?: string;

    /**
     * Skip the hosts-file layer entirely even if the file exists.
     * Useful for forwarder setups that don't want host overrides.
     */
    skipHosts?: boolean;

    /**
     * Per-nameserver backend builder. Called once per
     * `parsed.nameservers` entry. Default: a UDP client built via
     * `UDPClient.request({dns, port})`. Override to use TCP, DoT,
     * DoH or a connection-pooled variant.
     */
    backend?: FailoverBackendBuilder;

    /**
     * Override the failover predicate. Default matches glibc / BIND
     * — see `FailoverBackend.defaultShouldFailover`.
     */
    shouldFailover?: FailoverPredicate;

    /**
     * Optional response cache between the StubResolver and the
     * upstream (FailoverBackend) layer. Disabled by default. See
     * `SystemResolverCache` for the accepted shapes.
     *
     * The cache sits *under* the hosts-file layer — local-only names
     * are still served from `/etc/hosts` first and never consume
     * cache slots. Only real network answers are cached.
     */
    cache?: SystemResolverCache;
};

/**
 * Default port forwarded to `UDPClient.request` when the resolv.conf
 * line doesn't specify one. resolver(5) parses port-suffixed
 * nameservers (e.g. `nameserver 1.1.1.1#5300`) into separate fields,
 * but our parser keeps the raw IP — port stays at 53 unless the
 * caller hand-builds a custom backend.
 */
const DEFAULT_NAMESERVER_PORT: number = 53;

const defaultBackend: FailoverBackendBuilder = ({host, port}) => UDPClient.request({
    dns: host,
    port: port ?? DEFAULT_NAMESERVER_PORT
});

/**
 * High-level convenience resolver that bundles the four building
 * blocks (`ResolvConf` + `HostsFile` + `FailoverBackend` +
 * `StubResolver`) into a single one-line setup:
 *
 * ```ts
 * const resolver = SystemResolver.system();
 * const response = await resolver.resolve('host', PacketTypes.A);
 * ```
 *
 * Pipeline (top to bottom):
 *
 *   StubResolver — search-path / ndots expansion
 *      ↓
 *   HostsFile — `/etc/hosts` first; NODATA halts, miss falls through
 *      ↓
 *   FailoverBackend — multi-nameserver retry / rotation per
 *                     `options.timeout` / `attempts` / `rotate`
 *      ↓
 *   UDPClient (per nameserver) — RFC 7766 §8 TC fallback to TCP
 *
 * Power users wire the same pieces by hand for finer control:
 *
 * ```ts
 * const conf = ResolvConf.fromFile();
 * const hosts = HostsFile.fromFile();
 * const failover = FailoverBackend.fromConfig(conf, ({host}) => DohClient.request({dns: host}));
 * const stub = StubResolver.fromConfig(conf, hosts.asResolverBackend(failover!));
 * ```
 *
 * The class itself is just a thin facade over `StubResolver`. The
 * `StubResolver` instance is exposed via `.stub` for callers that
 * want to access `expand()`, the search list, ndots, etc.
 */
export class SystemResolver {

    protected _stub: StubResolver;
    protected _cache: DnsCache | null;

    public constructor(stub: StubResolver, cache: DnsCache | null = null) {
        this._stub = stub;
        this._cache = cache;
    }

    /**
     * Read `/etc/resolv.conf` + `/etc/hosts` from disk and build the
     * full pipeline. Throws when `/etc/resolv.conf` is missing or
     * lists no nameservers — there's nothing meaningful to do without
     * an upstream. A missing `/etc/hosts` is silently ignored.
     */
    public static system(options: SystemResolverOptions = {}): SystemResolver {
        const conf = ResolvConf.fromFile(options.resolvConfPath ?? ResolvConf.DEFAULT_PATH);

        let hosts: HostsFile | null = null;

        if (options.skipHosts !== true) {
            const hostsPath = options.hostsPath ?? HostsFile.DEFAULT_PATH;

            try {
                hosts = HostsFile.fromFile(hostsPath);
            } catch (err) {
                // Tolerate ENOENT / permission denied — glibc does the
                // same. Surface anything else (corrupt file, etc.)
                // would still be useful to spot, but the file is
                // tolerant by design and ignores unparseable lines, so
                // a truly catastrophic read failure is the most likely
                // remaining cause and warrants the throw.
                const e = err as NodeJS.ErrnoException;

                if (e.code !== 'ENOENT' && e.code !== 'EACCES' && e.code !== 'EPERM') {
                    throw err;
                }
            }
        }

        return SystemResolver.fromConfig(conf, {
            hostsFile: hosts ?? undefined,
            backend: options.backend,
            shouldFailover: options.shouldFailover,
            cache: options.cache
        });
    }

    /**
     * Build a `SystemResolver` from a pre-parsed resolv.conf and
     * (optionally) a `HostsFile`. Same wiring as `system()` but
     * doesn't touch the filesystem. Useful for tests, embedded use,
     * and callers that already cached the parsed config.
     */
    public static fromConfig(
        conf: ParsedResolvConf,
        options: {
            hostsFile?: HostsFile;
            backend?: FailoverBackendBuilder;
            shouldFailover?: FailoverPredicate;
            cache?: SystemResolverCache;
        } = {}
    ): SystemResolver {
        const failover = FailoverBackend.fromConfig(conf, options.backend ?? defaultBackend, {
            shouldFailover: options.shouldFailover
        });

        if (failover === null) {
            throw new Error('SystemResolver: resolv.conf carries no `nameserver` entries');
        }

        // Cache wraps the upstream (failover) before hosts — so /etc/hosts
        // stays authoritative for local names and only network answers
        // consume cache slots.
        const cacheInstance = SystemResolver._resolveCacheOption(options.cache);
        const cachedUpstream: StubResolverBackend = cacheInstance !== null
            ? new CachedStubBackend(failover, {cache: cacheInstance}).resolve
            : failover;

        const backend: StubResolverBackend = options.hostsFile !== undefined
            ? options.hostsFile.asResolverBackend(cachedUpstream)
            : cachedUpstream;

        const stub = StubResolver.fromConfig(conf, backend);

        return new SystemResolver(stub, cacheInstance);
    }

    /**
     * Map a `SystemResolverCache` option to a concrete `DnsCache` (or
     * `null` for the no-cache default).
     *
     * @param {SystemResolverCache|undefined} option
     * @return {DnsCache|null}
     * @protected
     */
    protected static _resolveCacheOption(option: SystemResolverCache | undefined): DnsCache | null {
        if (option === undefined || option === false) {
            return null;
        }

        if (option === true) {
            return new DnsCache();
        }

        if (option instanceof DnsCache) {
            return option;
        }

        return new DnsCache(option);
    }

    /**
     * Resolve `name` per the full pipeline. See `StubResolver.resolve`
     * for the search-path / fall-through semantics — every layer
     * underneath the stub is transport detail.
     */
    public resolve(
        name: string,
        type: PacketTypes | number,
        cls: PacketClass | number = PacketClass.IN
    ): Promise<Packet> {
        return this._stub.resolve(name, type, cls);
    }

    /**
     * Underlying `StubResolver` — exposes `expand()`, `search`,
     * `ndots` for callers that want to inspect the search-path
     * configuration without unwrapping the layers themselves.
     */
    public get stub(): StubResolver {
        return this._stub;
    }

    /**
     * The active `DnsCache` instance, or `null` when caching was not
     * enabled at construction. Exposed so callers can call `.clear()`
     * on config reload, `.size()` for instrumentation, or pre-populate
     * with entries.
     */
    public get cache(): DnsCache | null {
        return this._cache;
    }

    /**
     * Lightweight wrapper around `fs.existsSync` so tests can verify
     * the system-file paths the helper would consult, without
     * actually triggering the read pipeline.
     */
    public static hasSystemFiles(options: Pick<SystemResolverOptions, 'resolvConfPath' | 'hostsPath'> = {}): {
        resolvConf: boolean;
        hosts: boolean;
    } {
        return {
            resolvConf: fs.existsSync(options.resolvConfPath ?? ResolvConf.DEFAULT_PATH),
            hosts: fs.existsSync(options.hostsPath ?? HostsFile.DEFAULT_PATH)
        };
    }

}