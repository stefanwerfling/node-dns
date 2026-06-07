import { EventEmitter } from 'events';
import { Dnssec } from '../Lib/Dnssec.js';
import { DNSKEY } from '../Packet/Types/DNSKEY.js';
import { DS } from '../Packet/Types/DS.js';
const REVOKE_BIT = 0x0080;
const SEP_BIT = 0x0001;
export class TrustAnchorManager extends EventEmitter {
    _initialAnchors;
    _addHoldDownMs;
    _removeHoldDownMs;
    _digestType;
    _now;
    _byZone = new Map();
    _seeded = new Set();
    constructor(options = {}) {
        super();
        this._initialAnchors = options.initialAnchors ?? [];
        this._addHoldDownMs = options.addHoldDownMs ?? 30 * 24 * 60 * 60 * 1000;
        this._removeHoldDownMs = options.removeHoldDownMs ?? 30 * 24 * 60 * 60 * 1000;
        this._digestType = options.digestType ?? 2;
        this._now = options.now ?? (() => Date.now());
        if (options.initialKeys) {
            for (const { zone: zone, key: key } of options.initialKeys) {
                const norm = TrustAnchorManager._normZone(zone);
                const bucket = this._byZone.get(norm) ?? [];
                bucket.push({ ...key });
                this._byZone.set(norm, bucket);
                this._seeded.add(norm);
            }
        }
    }
    static fromSerialized(state, options = {}) {
        return new TrustAnchorManager({
            ...options,
            initialKeys: state.keys
        });
    }
    serialize() {
        const keys = [];
        for (const [zone, bucket] of this._byZone) {
            for (const key of bucket) {
                if (key.state === 'Removed') {
                    continue;
                }
                keys.push({ zone: zone, key: { ...key } });
            }
        }
        return { version: 1, keys: keys };
    }
    update(zone, records) {
        const norm = TrustAnchorManager._normZone(zone);
        const events = [];
        const now = this._now();
        const observed = [];
        const observedTags = new Set();
        for (const r of records) {
            if (!(r.packetType instanceof DNSKEY)) {
                continue;
            }
            const dnskey = r.packetType;
            const flags = dnskey.flags;
            if ((flags & SEP_BIT) === 0) {
                continue;
            }
            const observation = {
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
        if (!seeded) {
            const dsAnchors = this._initialAnchors.filter((a) => TrustAnchorManager._normZone(a.zone) === norm);
            for (const observation of observed) {
                const dnskey = TrustAnchorManager._reifyDnskey(observation);
                const ownerForDs = norm === '' ? '.' : `${norm}.`;
                for (const anchor of dsAnchors) {
                    const ds = anchor.ds;
                    let matches = false;
                    try {
                        matches = Dnssec.verifyDs(ownerForDs, dnskey, ds);
                    }
                    catch {
                        matches = false;
                    }
                    if (matches) {
                        observation.state = 'Valid';
                        events.push({ type: 'added', zone: norm, keyTag: observation.keyTag });
                        break;
                    }
                }
            }
        }
        for (const existing of bucket) {
            if (existing.state === 'Removed') {
                continue;
            }
            const stillThere = observed.find((o) => o.keyTag === existing.keyTag && o.key === existing.key);
            if (stillThere) {
                existing.lastSeenAt = now;
                if ((stillThere.flags & REVOKE_BIT) !== 0) {
                    if (existing.state !== 'Revoked') {
                        existing.state = 'Revoked';
                        existing.stateChangedAt = now;
                        events.push({ type: 'revoked', zone: norm, keyTag: existing.keyTag });
                    }
                    continue;
                }
                if (existing.state === 'AddPending' && now - existing.stateChangedAt >= this._addHoldDownMs) {
                    existing.state = 'Valid';
                    existing.stateChangedAt = now;
                    events.push({ type: 'promoted', zone: norm, keyTag: existing.keyTag });
                }
                else if (existing.state === 'Missing') {
                    existing.state = 'Valid';
                    existing.stateChangedAt = now;
                    events.push({ type: 'restored', zone: norm, keyTag: existing.keyTag });
                }
                else {
                    events.push({ type: 'observed', zone: norm, keyTag: existing.keyTag });
                }
            }
            else {
                if (existing.state === 'AddPending') {
                    existing.state = 'Removed';
                    existing.stateChangedAt = now;
                    events.push({ type: 'removed', zone: norm, keyTag: existing.keyTag });
                }
                else if (existing.state === 'Valid') {
                    existing.state = 'Missing';
                    existing.stateChangedAt = now;
                    events.push({ type: 'missing', zone: norm, keyTag: existing.keyTag });
                }
                else if (existing.state === 'Missing' && now - existing.stateChangedAt >= this._removeHoldDownMs) {
                    existing.state = 'Removed';
                    existing.stateChangedAt = now;
                    events.push({ type: 'removed', zone: norm, keyTag: existing.keyTag });
                }
                else if (existing.state === 'Revoked' && now - existing.stateChangedAt >= this._removeHoldDownMs) {
                    existing.state = 'Removed';
                    existing.stateChangedAt = now;
                    events.push({ type: 'removed', zone: norm, keyTag: existing.keyTag });
                }
            }
        }
        for (const observation of observed) {
            const already = bucket.find((b) => b.keyTag === observation.keyTag && b.key === observation.key);
            if (already !== undefined) {
                continue;
            }
            if ((observation.flags & REVOKE_BIT) !== 0) {
                continue;
            }
            bucket.push(observation);
            if (observation.state === 'Valid') {
                continue;
            }
            events.push({ type: 'added', zone: norm, keyTag: observation.keyTag });
        }
        const live = bucket.filter((b) => b.state !== 'Removed');
        if (live.length !== bucket.length) {
            this._byZone.set(norm, live);
        }
        else {
            this._byZone.set(norm, bucket);
        }
        this._seeded.add(norm);
        for (const e of events) {
            this.emit(e.type, e);
        }
        return events;
    }
    currentAnchors(zone) {
        const norm = TrustAnchorManager._normZone(zone);
        if (!this._seeded.has(norm)) {
            return this._initialAnchors
                .filter((a) => TrustAnchorManager._normZone(a.zone) === norm)
                .map((a) => ({ zone: a.zone, ds: a.ds }));
        }
        const bucket = this._byZone.get(norm) ?? [];
        const out = [];
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
                out.push({ zone: ownerForDs, ds: ds });
            }
            catch {
            }
        }
        return out;
    }
    getKeys(zone) {
        const bucket = this._byZone.get(TrustAnchorManager._normZone(zone)) ?? [];
        return bucket.map((k) => ({ ...k }));
    }
    forgetZone(zone) {
        const norm = TrustAnchorManager._normZone(zone);
        this._byZone.delete(norm);
        this._seeded.delete(norm);
    }
    static _reifyDnskey(key) {
        const dnskey = new DNSKEY(key.flags, 3, key.algorithm, key.key);
        dnskey.keyTag = key.keyTag;
        return dnskey;
    }
    static _normZone(zone) {
        if (zone === '.' || zone === '') {
            return '';
        }
        const stripped = zone.endsWith('.') ? zone.slice(0, -1) : zone;
        return stripped.toLowerCase();
    }
}
//# sourceMappingURL=TrustAnchorManager.js.map