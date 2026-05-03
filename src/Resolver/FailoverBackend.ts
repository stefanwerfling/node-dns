import type {ParsedResolvConf} from '../Lib/ResolvConf.js';
import {Packet} from '../Packet/Packet.js';
import {RCODE} from './RecursiveResolver.js';
import type {StubResolverBackend} from './StubResolver.js';

/**
 * Whether a given outcome on one upstream should trigger a failover
 * to the next configured upstream. Receives either the parsed
 * response or the thrown error.
 *
 *  - For an `Error`: typically a timeout or a network failure — almost
 *    always failover.
 *  - For a `Packet`: inspect `header.rcode`. The default predicate
 *    fails over on `SERVFAIL` only; `NXDOMAIN`, `NOERROR`,
 *    `REFUSED`, `FORMERR`, `NOTIMP` are returned to the caller
 *    verbatim so definitive answers aren't masked by retries.
 */
export type FailoverPredicate = (resultOrError: Packet | Error) => boolean;

export type FailoverOptions = {
    /**
     * Per-attempt timeout in milliseconds. resolver(5) `options.timeout`
     * default is 5 seconds. `0` disables the timeout (defer to
     * whatever the backend itself enforces).
     */
    timeoutMs?: number;

    /**
     * Number of attempts per backend before failing over. resolver(5)
     * `options.attempts` default is 2. Each retry counts against the
     * total work — the second attempt only fires if the first met the
     * `shouldFailover` predicate.
     */
    attempts?: number;

    /**
     * Round-robin the starting backend across calls instead of always
     * starting at index 0. resolver(5) `options.rotate` flag.
     * Distributes load across upstreams when the first server is
     * healthy too.
     */
    rotate?: boolean;

    /**
     * Predicate deciding whether a given outcome triggers failover.
     * Default: `Error` always fails over; `Packet` fails over only on
     * `SERVFAIL`.
     */
    shouldFailover?: FailoverPredicate;
};

/**
 * Builder that turns a target descriptor (host, optional port, optional
 * protocol hint) into a `StubResolverBackend`. Used by `fromConfig` so
 * the caller can pick UDP / TCP / DoT / DoH per nameserver without the
 * failover layer needing to know any of those transport details.
 */
export type FailoverBackendBuilder = (target: {
    host: string;
    port?: number;
}) => StubResolverBackend;

const defaultPredicate: FailoverPredicate = (r) => {
    if (r instanceof Error) {
        return true;
    }

    return r.header.rcode === RCODE.SERVFAIL;
};

const withTimeout = <T>(promise: Promise<T>, timeoutMs: number, label: string): Promise<T> => {
    if (timeoutMs <= 0) {
        return promise;
    }

    return new Promise<T>((resolve, reject) => {
        const timer = setTimeout(() => {
            reject(new Error(`FailoverBackend: ${label} exceeded ${timeoutMs}ms`));
        }, timeoutMs);

        promise.then(
            (v) => {
                clearTimeout(timer);
                resolve(v);
            },
            (err) => {
                clearTimeout(timer);
                reject(err instanceof Error ? err : new Error(String(err)));
            }
        );
    });
};

/**
 * Multi-upstream failover wrapper for `StubResolverBackend`s.
 *
 * Composes N backends into one. Each call walks the backends in order
 * (rotated per call when `rotate: true`), retrying each up to
 * `attempts` times before moving on, until one returns an outcome the
 * `shouldFailover` predicate considers definitive. The default
 * predicate matches glibc / BIND: anything that throws (timeout,
 * network error) and `SERVFAIL` responses fail over; `NXDOMAIN`,
 * `NOERROR`, `REFUSED`, `FORMERR`, `NOTIMP` are returned immediately.
 *
 * If every (backend × attempt) tuple fails, the *last* outcome is
 * surfaced — so the caller sees the most recent SERVFAIL or the most
 * recent thrown error. That's what resolver(5) does and what
 * StubResolver expects so it can stop walking the search list on a
 * non-NXDOMAIN final response.
 *
 * Designed to slot under `StubResolver`:
 *
 * ```ts
 * const conf = ResolvConf.fromFile();
 * const backend = FailoverBackend.fromConfig(conf, ({host, port}) =>
 *   UDPClient.request({dns: host, port: port}));
 * const stub = StubResolver.fromConfig(conf, backend);
 * ```
 *
 * **Out of scope:** parallel-fan-out (every backend simultaneously,
 * first non-failover wins). resolver(5) is sequential by design;
 * callers that want fan-out can hand-build it on top of
 * `StubResolverBackend`.
 */
export class FailoverBackend {

    /**
     * Combine `backends` into a single `StubResolverBackend` with
     * retry, timeout and optional rotation.
     *
     * Throws synchronously when `backends` is empty.
     */
    public static combine(
        backends: StubResolverBackend[],
        options: FailoverOptions = {}
    ): StubResolverBackend {
        if (backends.length === 0) {
            throw new Error('FailoverBackend.combine: at least one backend is required');
        }

        const timeoutMs = options.timeoutMs ?? 5000;
        const attempts = Math.max(1, options.attempts ?? 2);
        const rotate = options.rotate === true;
        const shouldFailover = options.shouldFailover ?? defaultPredicate;

        // Closure-local rotation cursor — round-robin across calls so
        // load gets distributed across healthy upstreams instead of
        // hammering the first.
        let rotationCursor = 0;

        return async(name, type, cls): Promise<Packet> => {
            const start = rotate ? rotationCursor++ % backends.length : 0;

            let lastError: Error | null = null;
            let lastPacket: Packet | null = null;

            for (let i = 0; i < backends.length; i++) {
                const backendIdx = (start + i) % backends.length;
                const backend = backends[backendIdx];

                for (let attempt = 0; attempt < attempts; attempt++) {
                    let outcome: Packet | Error;

                    try {
                        outcome = await withTimeout(
                            backend(name, type, cls),
                            timeoutMs,
                            `backend ${backendIdx} attempt ${attempt + 1}`
                        );
                    } catch (err) {
                        outcome = err instanceof Error ? err : new Error(String(err));
                    }

                    if (outcome instanceof Error) {
                        lastError = outcome;
                        lastPacket = null;
                    } else {
                        lastPacket = outcome;
                        lastError = null;
                    }

                    if (!shouldFailover(outcome)) {
                        return outcome as Packet;
                    }
                    // else: try next attempt (or next backend on the
                    // last attempt of this backend).
                }
            }

            // Every backend × attempt exhausted. Surface the last
            // outcome — the StubResolver above us will react to it as
            // it would to a single-backend response (e.g. SERVFAIL
            // halts the search list, so transient upstream outage
            // doesn't get masked by walking the whole search list).
            if (lastPacket !== null) {
                return lastPacket;
            }

            throw lastError ?? new Error('FailoverBackend: exhausted with no outcome');
        };
    }

    /**
     * Build a failover backend straight from a parsed `/etc/resolv.conf`.
     * Wires `options.timeout` (seconds → ms), `options.attempts` and
     * `options.rotate` from the file. The caller supplies a `builder`
     * that turns each `nameserver` IP into a transport-specific backend
     * (typically `UDPClient.request(...)`).
     *
     * Returns `null` when `parsed.nameservers` is empty so the caller
     * can fall back to a recursive resolver / public DNS / etc. without
     * a try/catch round.
     */
    public static fromConfig(
        parsed: ParsedResolvConf,
        builder: FailoverBackendBuilder,
        options: Pick<FailoverOptions, 'shouldFailover'> = {}
    ): StubResolverBackend | null {
        if (parsed.nameservers.length === 0) {
            return null;
        }

        const backends = parsed.nameservers.map((host) => builder({host: host}));

        // resolver(5) `options.timeout` is in seconds.
        const timeoutMs = parsed.options.timeout !== undefined
            ? parsed.options.timeout * 1000
            : undefined;

        return FailoverBackend.combine(backends, {
            timeoutMs: timeoutMs,
            attempts: parsed.options.attempts,
            rotate: parsed.options.rotate,
            shouldFailover: options.shouldFailover
        });
    }

    /**
     * Default failover predicate exposed for callers that want to
     * extend it (e.g. "also fail over on REFUSED" — common in BIND
     * deployments behind ACLs).
     */
    public static readonly defaultShouldFailover: FailoverPredicate = defaultPredicate;

}