import {PacketResource} from '../Packet/PacketResource.js';
import {MdnsServer} from './MdnsServer.js';

/**
 * Default Apple-style back-off schedule for re-announcing records
 * after a successful probe (RFC 6762 §8.3 / §10). The probe phase
 * already sent two unsolicited responses; these intervals govern the
 * follow-on schedule. Each entry is the delay *from the previous
 * announcement* (or from `start()` for the first entry).
 */
const DEFAULT_SCHEDULE: number[] = [1000, 2000, 4000, 8000];

export type MdnsAnnouncerOptions = {
    /**
     * Sequence of delays (ms) — first delay measured from `start()`,
     * subsequent delays from the previous announcement. Default
     * `[1000, 2000, 4000, 8000]`. Pass an empty array `[]` to skip
     * the back-off and rely on `steadyStateMs` alone.
     */
    schedule?: number[];

    /**
     * After the back-off schedule completes, keep re-announcing every
     * `steadyStateMs` ms. `0` (default) stops the announcer once the
     * schedule is exhausted — recommended only when the records have
     * generous TTLs and you don't expect link churn.
     */
    steadyStateMs?: number;

    /**
     * When `stop()` is called, send a goodbye (TTL=0) before resolving
     * so peer caches drop the entry immediately instead of waiting for
     * natural TTL expiry. Default `true`.
     */
    goodbyeOnStop?: boolean;

    /**
     * Send one announcement immediately when `start()` is called,
     * before the first scheduled delay. Default `false` — assumes
     * `MdnsProbe` already announced post-probe. Flip to `true` when
     * driving the announcer without a prior probe phase.
     */
    initialAnnounce?: boolean;
};

/**
 * Lifecycle helper that schedules unsolicited mDNS announcements
 * (RFC 6762 §10) on top of `MdnsServer.announce()`. Composition target
 * for the typical post-probe flow:
 *
 * ```ts
 * const result = await MdnsProbe.claim({records, announceAttempts: 2});
 *
 * if (result.result === 'claimed') {
 *   await server.listen();
 *   server.on('request', handler);
 *
 *   const announcer = new MdnsAnnouncer(server, records).start();
 *   // ... app runs, serving DNS-SD queries ...
 *   await announcer.stop();   // → sends goodbye, cancels timers
 *   server.close();
 * }
 * ```
 *
 * The announcer holds a reference to the records, not a snapshot —
 * mutating the array between ticks is safe (each tick reads the
 * current contents), but the records themselves still must not be
 * mutated since `MdnsServer.announce` copies them before stamping
 * the cache-flush bit. Immutable record instances are the simplest
 * shape.
 *
 * Errors raised inside `server.announce()` (socket already closed,
 * dgram send failure) are forwarded to an `error` listener if one
 * is registered, otherwise swallowed — a transient send failure
 * shouldn't kill the whole schedule.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc6762#section-10
 */
export class MdnsAnnouncer {

    protected _server: MdnsServer;
    protected _records: PacketResource[];
    protected _schedule: number[];
    protected _steadyStateMs: number;
    protected _goodbyeOnStop: boolean;
    protected _initialAnnounce: boolean;

    protected _timer: NodeJS.Timeout | null;
    protected _stepIndex: number;
    protected _running: boolean;
    protected _onError: ((err: Error) => void) | null;

    public constructor(
        server: MdnsServer,
        records: PacketResource[],
        options: MdnsAnnouncerOptions = {}
    ) {
        this._server = server;
        this._records = records;
        this._schedule = options.schedule ?? DEFAULT_SCHEDULE.slice();
        this._steadyStateMs = Math.max(0, options.steadyStateMs ?? 0);
        this._goodbyeOnStop = options.goodbyeOnStop ?? true;
        this._initialAnnounce = options.initialAnnounce ?? false;

        this._timer = null;
        this._stepIndex = 0;
        this._running = false;
        this._onError = null;
    }

    /**
     * Begin scheduling announcements. Idempotent — calling `start()`
     * on an already-running announcer is a no-op (saves callers from
     * tracking lifecycle state themselves).
     */
    public start(): this {
        if (this._running) {
            return this;
        }

        this._running = true;
        this._stepIndex = 0;

        if (this._initialAnnounce) {
            this._announce();
        }

        this._scheduleNext();
        return this;
    }

    /**
     * Stop the schedule. When `goodbyeOnStop` is true (the default),
     * sends a TTL=0 announcement so peer caches flush our records
     * before the announcer is torn down. Resolves once the goodbye
     * datagram has been queued to the kernel.
     *
     * Idempotent — calling `stop()` more than once is safe and the
     * second call resolves immediately.
     */
    public async stop(): Promise<void> {
        if (!this._running) {
            return;
        }

        this._running = false;

        if (this._timer !== null) {
            clearTimeout(this._timer);
            this._timer = null;
        }

        if (this._goodbyeOnStop && this._records.length > 0) {
            try {
                await this._server.goodbye(this._records);
            } catch (err) {
                this._reportError(err);
            }
        }
    }

    /**
     * Subscribe to errors from `server.announce()` / `server.goodbye()`
     * calls fired by the schedule. Without a listener, errors are
     * silently swallowed so a transient send failure (e.g. socket
     * closed mid-tick) doesn't take the schedule with it. Multiple
     * `on('error', ...)` registrations are not supported — the latest
     * wins.
     */
    public on(event: 'error', listener: (err: Error) => void): this {
        if (event === 'error') {
            this._onError = listener;
        }

        return this;
    }

    /**
     * Whether the announcer is currently scheduling ticks. False
     * before `start()` and after `stop()` (or after the schedule
     * completes when `steadyStateMs === 0`).
     */
    public get running(): boolean {
        return this._running;
    }

    protected _scheduleNext(): void {
        if (!this._running) {
            return;
        }

        let delay: number;

        if (this._stepIndex < this._schedule.length) {
            delay = this._schedule[this._stepIndex];
        } else if (this._steadyStateMs > 0) {
            delay = this._steadyStateMs;
        } else {
            // Schedule exhausted, no steady-state — quiet stop. Don't
            // emit goodbye here; the caller may still want the
            // records advertised on incoming queries via the live
            // `MdnsServer`. Goodbye is reserved for explicit `stop()`.
            this._running = false;
            return;
        }

        this._timer = setTimeout(() => {
            this._timer = null;
            this._stepIndex++;
            this._announce();
            this._scheduleNext();
        }, delay);

        this._timer.unref?.();
    }

    protected _announce(): void {
        if (this._records.length === 0) {
            return;
        }

        // Fire-and-forget; capture rejection so the schedule keeps
        // ticking even if a single send fails.
        this._server.announce(this._records).catch((err) => this._reportError(err));
    }

    protected _reportError(err: unknown): void {
        if (this._onError !== null) {
            this._onError(err instanceof Error ? err : new Error(String(err)));
        }
    }

}