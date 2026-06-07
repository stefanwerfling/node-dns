import {EventEmitter} from 'events';
import {Dnssec} from '../Lib/Dnssec.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {DNSKEY} from '../Packet/Types/DNSKEY.js';
import {DS} from '../Packet/Types/DS.js';
import {TrustAnchor} from './TrustAnchor.js';

/**
 * RFC 5011 key state.
 *
 *  - **AddPending** — first observed; not yet trusted. Promoted to
 *    `Valid` when continuously visible across the add-hold-down
 *    window.
 *  - **Valid** — currently a trust anchor.
 *  - **Missing** — was Valid, absent in last refresh; will be
 *    `Removed` once the remove-hold-down window elapses with no
 *    reappearance.
 *  - **Revoked** — the operator destroyed the key (REVOKE bit, RFC
 *    5011 §2.1). Permanent — revoked keys never come back.
 *  - **Removed** — terminal; kept briefly so observability events
 *    can fire before the entry is garbage-collected.
 */
export type KeyState = 'AddPending' | 'Valid' | 'Missing' | 'Revoked' | 'Removed';

/**
 * Per-key state row inside the manager.
 */
export type ManagedKey = {
    /** RFC 4034 §5.1.4 key tag (calculated over the wire DNSKEY). */
    keyTag: number;
    /** Raw 16-bit DNSKEY flags. SEP, ZK, REVOKE all live here. */
    flags: number;
    /** DNSSEC algorithm number. */
    algorithm: number;
    /** Base64 public-key bytes — same shape `DNSKEY.key` carries. */
    key: string;
    /** Current state in the RFC 5011 state machine. */
    state: KeyState;
    /** Epoch ms the key was first observed. */
    addedAt: number;
    /** Epoch ms of the latest observation (any state). */
    lastSeenAt: number;
    /** Epoch ms of the latest state transition (drives hold-down). */
    stateChangedAt: number;
};

/**
 * Result of one `update()` call — a flat list of state transitions
 * the manager just applied. Useful for metrics and for piping into a
 * persistence layer that wants to know what changed.
 */
export type RolloverEvent = {
    type: 'added' | 'promoted' | 'missing' | 'restored' | 'revoked' | 'removed' | 'observed';
    zone: string;
    keyTag: number;
};

/**
 * Constructor options for `TrustAnchorManager`.
 */
export type TrustAnchorManagerOptions = {
    /**
     * Static trust anchors known at startup. The classic case is
     * `TrustAnchors.DEFAULT` (IANA root KSK as DS). On the first
     * `update()` for the anchor's zone, the manager matches the
     * incoming DNSKEYs against these DS digests and seeds matching
     * keys directly into the `Valid` state — no add-hold-down for
     * keys we already trust.
     */
    initialAnchors?: ReadonlyArray<TrustAnchor>;

    /**
     * Optional pre-recorded `ManagedKey` rows to rehydrate the state
     * machine after a restart. Pair with `serialize()` to survive
     * process bounces without losing hold-down timers.
     */
    initialKeys?: ReadonlyArray<{zone: string; key: ManagedKey;}>;

    /**
     * Add-hold-down window (ms). RFC 5011 §2.1 recommends 30 days for
     * the root zone. Tests pass a tiny value plus a fake clock.
     */
    addHoldDownMs?: number;

    /**
     * Remove-hold-down window (ms). RFC 5011 §2.1 recommends 30 days
     * — when a previously-Valid key has been absent for this long,
     * drop it. Independent from add-hold-down.
     */
    removeHoldDownMs?: number;

    /**
     * DS digest type used when materialising `currentAnchors()`.
     * Default 2 (SHA-256, RFC 4509). Match the digest type used by
     * the parent's DS records so trust-anchor synthesis matches the
     * delegation in the validator's eyes.
     */
    digestType?: number;

    /**
     * Injectable clock for deterministic tests. Defaults to
     * `Date.now`.
     */
    now?: () => number;
};

/**
 * Serialised snapshot of the manager — every Valid / AddPending /
 * Missing / Revoked key, keyed by zone. Round-trips through
 * `TrustAnchorManager.fromSerialized()`.
 */
export type SerializedTrustAnchorState = {
    version: 1;
    keys: Array<{zone: string; key: ManagedKey;}>;
};

/**
 * Internal — DNSKEY REVOKE bit (RFC 5011 §2.1, flag bit 8 from the
 * MSB). The bit lives in the high byte of `flags`; the value
 * therefore is `0x0080` on the 16-bit field.
 */
const REVOKE_BIT: number = 0x0080;

/**
 * Internal — SEP (Secure Entry Point) bit (RFC 4034 §2.1.1, flag
 * bit 15 from the MSB). Trust anchors are KSKs i.e. SEP-flagged
 * DNSKEYs.
 */
const SEP_BIT: number = 0x0001;

/**
 * RFC 5011 trust-anchor lifecycle manager.
 *
 * Holds a per-zone view of every observed KSK plus its state in the
 * add/remove-hold-down protocol (§3-6 of RFC 5011). The state
 * machine is purely event-driven: the caller hands in a *validated*
 * DNSKEY response via `update(zone, records)` and the manager
 * applies the transitions. Validation itself stays in
 * `DnssecValidator` — the manager trusts that what it sees has
 * already verified against the *currently Valid* anchor set, so it
 * never gets a chance to slip an attacker-injected key into the
 * trust pool.
 *
 * Scheduling the periodic refresh is the caller's job. The classic
 * pattern is "once a day, fetch `<zone>/DNSKEY`, hand the validated
 * answer to the manager, persist the serialised state". The manager
 * has no built-in timer; embedding it in a resolver lets the
 * deployment decide whether to refresh from cron, from an
 * application loop, or in-process via the resolver itself.
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc5011
 */
export class TrustAnchorManager extends EventEmitter {

    protected _initialAnchors: ReadonlyArray<TrustAnchor>;
    protected _addHoldDownMs: number;
    protected _removeHoldDownMs: number;
    protected _digestType: number;
    protected _now: () => number;
    protected _byZone: Map<string, ManagedKey[]> = new Map();
    /** Zones we've already seen the first DNSKEY response for. */
    protected _seeded: Set<string> = new Set();

    public constructor(options: TrustAnchorManagerOptions = {}) {
        super();

        this._initialAnchors = options.initialAnchors ?? [];
        this._addHoldDownMs = options.addHoldDownMs ?? 30 * 24 * 60 * 60 * 1000;
        this._removeHoldDownMs = options.removeHoldDownMs ?? 30 * 24 * 60 * 60 * 1000;
        this._digestType = options.digestType ?? 2;
        this._now = options.now ?? ((): number => Date.now());

        if (options.initialKeys) {
            for (const {zone: zone, key: key} of options.initialKeys) {
                const norm = TrustAnchorManager._normZone(zone);
                const bucket = this._byZone.get(norm) ?? [];
                bucket.push({...key});
                this._byZone.set(norm, bucket);
                this._seeded.add(norm);
            }
        }
    }

    /**
     * Rehydrate a previously-`serialize()`d state. The new manager
     * inherits the timestamps recorded inside the snapshot, so a
     * key that was halfway through its add-hold-down before the
     * restart resumes from the same point — `update()` sees an
     * accurate clock-delta against `stateChangedAt`.
     *
     * @param {SerializedTrustAnchorState} state
     * @param {TrustAnchorManagerOptions} options
     * @return {TrustAnchorManager}
     */
    public static fromSerialized(
        state: SerializedTrustAnchorState,
        options: Omit<TrustAnchorManagerOptions, 'initialKeys'> = {}
    ): TrustAnchorManager {
        return new TrustAnchorManager({
            ...options,
            initialKeys: state.keys
        });
    }

    /**
     * Snapshot the full state so it can be persisted across restarts.
     *
     * @return {SerializedTrustAnchorState}
     */
    public serialize(): SerializedTrustAnchorState {
        const keys: Array<{zone: string; key: ManagedKey;}> = [];

        for (const [zone, bucket] of this._byZone) {
            for (const key of bucket) {
                if (key.state === 'Removed') {
                    continue;
                }

                keys.push({zone: zone, key: {...key}});
            }
        }

        return {version: 1, keys: keys};
    }

    /**
     * Apply the RFC 5011 state machine for `zone` based on the
     * just-validated DNSKEY records in `records`. The caller asserts
     * that those records have been verified against the *current*
     * trust anchor set — the manager does not re-validate.
     *
     * @param {string} zone
     * @param {PacketResource[]} records the answer section of a
     *   DNSKEY query — non-DNSKEY records are ignored.
     * @return {RolloverEvent[]}
     */
    public update(zone: string, records: ReadonlyArray<PacketResource>): RolloverEvent[] {
        const norm = TrustAnchorManager._normZone(zone);
        const events: RolloverEvent[] = [];
        const now = this._now();

        const observed: ManagedKey[] = [];
        const observedTags = new Set<number>();

        for (const r of records) {
            if (!(r.packetType instanceof DNSKEY)) {
                continue;
            }

            const dnskey = r.packetType;
            const flags = dnskey.flags;

            // Only KSKs (SEP-flagged) participate in RFC 5011 — ZSKs
            // are not trust anchors so a rollover of one doesn't
            // touch the manager.
            // eslint-disable-next-line no-bitwise
            if ((flags & SEP_BIT) === 0) {
                continue;
            }

            const observation: ManagedKey = {
                keyTag: dnskey.keyTag,
                flags: flags,
                algorithm: dnskey.algorithm,
                key: dnskey.key,
                state: 'AddPending',
                addedAt: now,
                lastSeenAt: now,
                stateChangedAt: now
            };

            observed.push(observation);
            observedTags.add(dnskey.keyTag);
        }

        const bucket = this._byZone.get(norm) ?? [];
        const seeded = this._seeded.has(norm);

        // First-observation seeding: if we have initialAnchors for
        // this zone, match observed DNSKEYs against the DS digests
        // and seed matching keys as Valid (no add-hold-down — we
        // were already configured to trust them).
        if (!seeded) {
            const dsAnchors = this._initialAnchors.filter((a) => TrustAnchorManager._normZone(a.zone) === norm);

            for (const observation of observed) {
                const dnskey = TrustAnchorManager._reifyDnskey(observation);
                const ownerForDs = norm === '' ? '.' : `${norm}.`;

                for (const anchor of dsAnchors) {
                    const ds = anchor.ds as DS;

                    let matches = false;

                    try {
                        matches = Dnssec.verifyDs(ownerForDs, dnskey, ds);
                    } catch {
                        matches = false;
                    }

                    if (matches) {
                        observation.state = 'Valid';
                        events.push({type: 'added', zone: norm, keyTag: observation.keyTag});
                        break;
                    }
                }
            }
        }

        // Walk existing keys and match against the observed set.
        for (const existing of bucket) {
            if (existing.state === 'Removed') {
                continue;
            }

            const stillThere = observed.find((o) => o.keyTag === existing.keyTag && o.key === existing.key);

            if (stillThere) {
                existing.lastSeenAt = now;

                // Revoke-bit semantics (§2.1): an existing trusted
                // key that now appears with REVOKE set must be
                // marked Revoked immediately.
                // eslint-disable-next-line no-bitwise
                if ((stillThere.flags & REVOKE_BIT) !== 0) {
                    if (existing.state !== 'Revoked') {
                        existing.state = 'Revoked';
                        existing.stateChangedAt = now;
                        events.push({type: 'revoked', zone: norm, keyTag: existing.keyTag});
                    }

                    continue;
                }

                if (existing.state === 'AddPending' && now - existing.stateChangedAt >= this._addHoldDownMs) {
                    existing.state = 'Valid';
                    existing.stateChangedAt = now;
                    events.push({type: 'promoted', zone: norm, keyTag: existing.keyTag});
                } else if (existing.state === 'Missing') {
                    existing.state = 'Valid';
                    existing.stateChangedAt = now;
                    events.push({type: 'restored', zone: norm, keyTag: existing.keyTag});
                } else {
                    events.push({type: 'observed', zone: norm, keyTag: existing.keyTag});
                }
            } else {
                // Key disappeared from the response.
                if (existing.state === 'AddPending') {
                    // §3: add-hold-down requires *continuous*
                    // visibility — a gap resets the candidate.
                    existing.state = 'Removed';
                    existing.stateChangedAt = now;
                    events.push({type: 'removed', zone: norm, keyTag: existing.keyTag});
                } else if (existing.state === 'Valid') {
                    existing.state = 'Missing';
                    existing.stateChangedAt = now;
                    events.push({type: 'missing', zone: norm, keyTag: existing.keyTag});
                } else if (existing.state === 'Missing' && now - existing.stateChangedAt >= this._removeHoldDownMs) {
                    existing.state = 'Removed';
                    existing.stateChangedAt = now;
                    events.push({type: 'removed', zone: norm, keyTag: existing.keyTag});
                } else if (existing.state === 'Revoked' && now - existing.stateChangedAt >= this._removeHoldDownMs) {
                    existing.state = 'Removed';
                    existing.stateChangedAt = now;
                    events.push({type: 'removed', zone: norm, keyTag: existing.keyTag});
                }
            }
        }

        // Append observations that aren't in the bucket yet.
        for (const observation of observed) {
            const already = bucket.find((b) => b.keyTag === observation.keyTag && b.key === observation.key);

            if (already !== undefined) {
                continue;
            }

            // eslint-disable-next-line no-bitwise
            if ((observation.flags & REVOKE_BIT) !== 0) {
                // A brand-new key with REVOKE set is meaningless — we
                // never trusted it, there is nothing to revoke. Skip.
                continue;
            }

            bucket.push(observation);

            if (observation.state === 'Valid') {
                // Already covered by the seeding loop above.
                continue;
            }

            events.push({type: 'added', zone: norm, keyTag: observation.keyTag});
        }

        // Garbage-collect terminally Removed rows.
        const live = bucket.filter((b) => b.state !== 'Removed');

        if (live.length !== bucket.length) {
            this._byZone.set(norm, live);
        } else {
            this._byZone.set(norm, bucket);
        }

        this._seeded.add(norm);

        for (const e of events) {
            this.emit(e.type, e);
        }

        return events;
    }

    /**
     * Return the current trust anchor set for `zone` materialised as
     * `TrustAnchor[]` (DS form, matching the validator's `findFor`
     * shape). Only `Valid` keys contribute.
     *
     * When the manager has no observation yet for `zone` (no `update()`
     * call), the static `initialAnchors` for that zone are returned —
     * a fresh-boot resolver behaves the same as the static-array case
     * until the first refresh primes the state machine.
     *
     * @param {string} zone
     * @return {TrustAnchor[]}
     */
    public currentAnchors(zone: string): TrustAnchor[] {
        const norm = TrustAnchorManager._normZone(zone);

        if (!this._seeded.has(norm)) {
            return this._initialAnchors
                .filter((a) => TrustAnchorManager._normZone(a.zone) === norm)
                .map((a) => ({zone: a.zone, ds: a.ds}));
        }

        const bucket = this._byZone.get(norm) ?? [];
        const out: TrustAnchor[] = [];

        for (const key of bucket) {
            if (key.state !== 'Valid') {
                continue;
            }

            const dnskey = TrustAnchorManager._reifyDnskey(key);
            const ownerForDs = norm === '' ? '.' : `${norm}.`;

            try {
                const digest = Dnssec.computeDsDigest(ownerForDs, dnskey, this._digestType);
                const keyTag = Dnssec.computeKeyTag(dnskey);
                const ds = new DS(keyTag, key.algorithm, this._digestType, digest);
                out.push({zone: ownerForDs, ds: ds});
            } catch {
                // Skip keys whose algorithm isn't supported by the
                // digest function — those can never anchor a chain
                // anyway.
            }
        }

        return out;
    }

    /**
     * Inspect the full state row for `zone`. Includes every state
     * (AddPending, Valid, Missing, Revoked). Useful for metrics
     * dashboards and key-rollover dashboards.
     *
     * @param {string} zone
     * @return {ManagedKey[]}
     */
    public getKeys(zone: string): ManagedKey[] {
        const bucket = this._byZone.get(TrustAnchorManager._normZone(zone)) ?? [];
        return bucket.map((k) => ({...k}));
    }

    /**
     * Drop every observation for `zone` and reset the seeding flag.
     * The next `update()` for the zone re-seeds from `initialAnchors`
     * as if it were the first observation. Useful for operator-driven
     * "I have a known-good snapshot, please re-bootstrap from it".
     *
     * @param {string} zone
     */
    public forgetZone(zone: string): void {
        const norm = TrustAnchorManager._normZone(zone);
        this._byZone.delete(norm);
        this._seeded.delete(norm);
    }

    protected static _reifyDnskey(key: ManagedKey): DNSKEY {
        const dnskey = new DNSKEY(key.flags, 3, key.algorithm, key.key);
        dnskey.keyTag = key.keyTag;
        return dnskey;
    }

    protected static _normZone(zone: string): string {
        if (zone === '.' || zone === '') {
            return '';
        }

        const stripped = zone.endsWith('.') ? zone.slice(0, -1) : zone;
        return stripped.toLowerCase();
    }

}