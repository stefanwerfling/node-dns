import {Dnssec, DnssecVerifyOptions} from '../Lib/Dnssec.js';
import {PacketResource} from '../Packet/PacketResource.js';
import {PacketTypes} from '../Packet/PacketTypes.js';
import {DNSKEY} from '../Packet/Types/DNSKEY.js';
import {DS} from '../Packet/Types/DS.js';
import {RRSIG} from '../Packet/Types/RRSIG.js';

/**
 * Validation outcome for one DNSSEC check.
 *
 * - **secure** — at least one RRSIG verified under a key the chain
 *   accepts.
 * - **insecure** — no RRSIG was offered for the RRset, *and* the
 *   parent zone proved no DS exists (or the caller chose to treat
 *   un-signed answers as insecure). The validator never produces
 *   `insecure` on its own — that classification is the resolver's
 *   responsibility, since it requires walking the chain.
 * - **bogus** — RRSIGs were present but none verified, or the chain
 *   itself was broken (no matching DNSKEY, parent DS mismatch, …).
 *   The resolver maps this to `SERVFAIL` per RFC 4035 §5.5.
 * - **indeterminate** — no anchor covers the answer's zone (e.g. the
 *   zone is outside any configured trust anchor's bailiwick). A
 *   permissive resolver passes the answer through with `AD=0`.
 */
export type DnssecValidity = 'secure' | 'insecure' | 'bogus' | 'indeterminate';

/**
 * Result of a single chain step.
 */
export type DnssecValidationResult = {
    validity: DnssecValidity;

    /**
     * Free-form explanation for `bogus` / `indeterminate` outcomes —
     * useful for logs and Extended-DNS-Errors. Absent for `secure`.
     */
    reason?: string;

    /**
     * Key the verification succeeded under (when `validity` is
     * `secure`). Useful for tracing chain decisions in tests.
     */
    byKey?: {keyTag: number; algorithm: number;};
};

/**
 * Chain-of-trust validator: composes the primitives in `Lib/Dnssec`
 * into the two operations a recursive resolver actually needs:
 *
 *  1. *Validate a zone's DNSKEY RRset against the parent's DS*. The
 *     `validateDnskeyRrset` step authenticates the keys the zone's
 *     other RRsets will be signed with.
 *  2. *Validate any RRset against the zone's authenticated DNSKEYs*.
 *     `validateRrset` does this.
 *
 * Together they let the resolver walk top-down — root DS → root
 * DNSKEY → tld DS → tld DNSKEY → … → answer RRset — and fail closed
 * the moment a step fails.
 *
 * The validator is stateless. The `RecursiveResolver` keeps the
 * authenticated DNSKEY set per-zone in a separate map; this class
 * just answers "given these inputs, does the math work out?".
 *
 * @docs https://datatracker.ietf.org/doc/html/rfc4035
 */
export class DnssecChain {

    /**
     * RFC 4034 §2.1.1: bit 15 of the flags field (the `0x0001` LSB)
     * marks a "Secure Entry Point" — by convention the zone's KSK.
     * KSKs are the keys that match a parent DS; ZSKs (no SEP flag) are
     * what the zone uses to sign normal RRsets, and ZSKs themselves
     * are signed by the KSK in the DNSKEY RRset's RRSIGs.
     */
    public static readonly SEP_FLAG: number = 0x0001;

    /**
     * RFC 4034 §2.1.1: bit 8 (`0x0100`) marks a key valid for zone
     * signing. RFC 4035 §5.3.1 requires this bit on any DNSKEY whose
     * RRSIG we are willing to honour for a non-DNSKEY RRset.
     */
    public static readonly ZONE_FLAG: number = 0x0100;

    /**
     * Validate a zone's DNSKEY RRset against the parent's DS records.
     *
     * Walks every DNSKEY that *could* be a KSK (SEP flag set), looks
     * for a parent-DS that matches it (`Dnssec.verifyDs`), and then
     * checks at least one RRSIG over the DNSKEY RRset verifies under
     * that KSK.
     *
     * `dnskeys` must be every DNSKEY at `zone` — the verifier needs
     * the entire RRset to compute the canonical signing input that
     * matches the way the signer constructed the RRSIG.
     *
     * @param {string} zone
     * @param {PacketResource[]} dnskeys
     * @param {PacketResource[]} rrsigs RRSIGs covering DNSKEY at `zone`
     * @param {ReadonlyArray<DS>} parentDs
     * @param {DnssecVerifyOptions} options
     * @return {DnssecValidationResult}
     */
    public static validateDnskeyRrset(
        zone: string,
        dnskeys: PacketResource[],
        rrsigs: PacketResource[],
        parentDs: ReadonlyArray<DS>,
        options: DnssecVerifyOptions = {}
    ): DnssecValidationResult {
        if (dnskeys.length === 0) {
            return {validity: 'bogus', reason: 'no DNSKEY records'};
        }

        if (rrsigs.length === 0) {
            return {validity: 'bogus', reason: 'no RRSIG over DNSKEY RRset'};
        }

        if (parentDs.length === 0) {
            return {validity: 'bogus', reason: 'no parent DS'};
        }

        // Find every DNSKEY that is *both* a KSK (SEP set) *and* matches
        // some parent-DS. Either both must hold for the key to anchor
        // the chain.
        const candidates: DNSKEY[] = [];

        for (const r of dnskeys) {
            if (!(r.packetType instanceof DNSKEY)) {
                continue;
            }

            const k = r.packetType;

            // eslint-disable-next-line no-bitwise
            if ((k.flags & DnssecChain.SEP_FLAG) === 0) {
                continue;
            }

            for (const ds of parentDs) {
                if (Dnssec.verifyDs(zone, k, ds)) {
                    candidates.push(k);
                    break;
                }
            }
        }

        if (candidates.length === 0) {
            return {validity: 'bogus', reason: 'no DNSKEY matches any parent DS'};
        }

        // For each candidate KSK, look for an RRSIG over the DNSKEY
        // RRset signed by that KSK and verify. We recompute the key
        // tag from the wire form rather than trusting `ksk.keyTag` —
        // the field is only populated by `PacketResource.decode`, so a
        // DNSKEY built fresh via `publicKeyToDnskey` carries `keyTag=0`.
        for (const ksk of candidates) {
            const kskTag = Dnssec.computeKeyTag(ksk);

            for (const sigResource of rrsigs) {
                if (!(sigResource.packetType instanceof RRSIG)) {
                    continue;
                }

                const sig = sigResource.packetType;

                if (sig.sigType !== PacketTypes.DNSKEY) {
                    continue;
                }

                if (sig.keyTag !== kskTag || sig.algorithm !== ksk.algorithm) {
                    continue;
                }

                let ok: boolean;

                try {
                    ok = Dnssec.verifyRrsig(zone, dnskeys, sig, ksk, options);
                } catch (e) {
                    // Unsupported algorithm / malformed key — treat as bogus.
                    return {validity: 'bogus', reason: e instanceof Error ? e.message : String(e)};
                }

                if (ok) {
                    return {validity: 'secure', byKey: {keyTag: kskTag, algorithm: ksk.algorithm}};
                }
            }
        }

        return {validity: 'bogus', reason: 'no RRSIG over DNSKEY verified under a DS-matched KSK'};
    }

    /**
     * Validate a non-DNSKEY RRset against an authenticated DNSKEY set.
     *
     * The caller is responsible for having validated `dnskeys`
     * upstream (typically via `validateDnskeyRrset`). The RRset
     * verifies if at least one supplied RRSIG matches a DNSKEY in the
     * set and the cryptographic check passes.
     *
     * Returns `insecure` when no RRSIGs cover the RRset — the *zone*
     * may still be unsigned (e.g. `example.com` has no DS at the
     * parent), and the resolver decides whether that's acceptable
     * based on the chain walk.
     *
     * @param {string} owner
     * @param {PacketResource[]} rrset
     * @param {PacketResource[]} rrsigs
     * @param {PacketResource[]} dnskeys
     * @param {DnssecVerifyOptions} options
     * @return {DnssecValidationResult}
     */
    public static validateRrset(
        owner: string,
        rrset: PacketResource[],
        rrsigs: PacketResource[],
        dnskeys: PacketResource[],
        options: DnssecVerifyOptions = {}
    ): DnssecValidationResult {
        if (rrset.length === 0) {
            return {validity: 'bogus', reason: 'rrset is empty'};
        }

        const rrType = rrset[0].packetType.type;
        const matchingSigs = DnssecChain.rrsigsFor(rrsigs, owner, rrType);

        if (matchingSigs.length === 0) {
            return {validity: 'insecure', reason: 'no RRSIG covers this RRset'};
        }

        const zoneKeys = DnssecChain._zoneKeys(dnskeys);

        if (zoneKeys.length === 0) {
            return {validity: 'bogus', reason: 'no DNSKEY with the ZONE flag'};
        }

        for (const sigResource of matchingSigs) {
            const sig = sigResource.packetType as RRSIG;

            for (const k of zoneKeys) {
                // Recompute the key tag — see note in `validateDnskeyRrset`.
                const tag = Dnssec.computeKeyTag(k);

                if (sig.keyTag !== tag || sig.algorithm !== k.algorithm) {
                    continue;
                }

                let ok: boolean;

                try {
                    ok = Dnssec.verifyRrsig(owner, rrset, sig, k, options);
                } catch (e) {
                    return {validity: 'bogus', reason: e instanceof Error ? e.message : String(e)};
                }

                if (ok) {
                    return {validity: 'secure', byKey: {keyTag: tag, algorithm: k.algorithm}};
                }
            }
        }

        return {validity: 'bogus', reason: 'no RRSIG verified under any zone DNSKEY'};
    }

    /**
     * Filter the supplied RRSIGs to those covering the named
     * `(owner, type)` RRset. The owner-name comparison is
     * case-insensitive and trailing-dot tolerant — DNS names are
     * case-insensitive at the protocol level (RFC 1035 §2.3.3).
     *
     * @param {PacketResource[]} rrsigs
     * @param {string} owner
     * @param {number} type
     * @return {PacketResource[]}
     */
    public static rrsigsFor(rrsigs: PacketResource[], owner: string, type: number): PacketResource[] {
        const target = DnssecChain._normalize(owner);
        const out: PacketResource[] = [];

        for (const r of rrsigs) {
            if (!(r.packetType instanceof RRSIG)) {
                continue;
            }

            if (r.packetType.sigType !== type) {
                continue;
            }

            if (DnssecChain._normalize(r.name) !== target) {
                continue;
            }

            out.push(r);
        }

        return out;
    }

    /**
     * Group records into RRsets keyed by `(name, type, class)`. Each
     * bucket preserves the input order. RRSIG and OPT records are
     * skipped — RRSIGs travel separately via `rrsigsFor`, and OPT is
     * a pseudo-record without an RRset.
     *
     * @param {PacketResource[]} records
     * @return {Map<string, PacketResource[]>}
     */
    public static groupRrsets(records: PacketResource[]): Map<string, PacketResource[]> {
        const out: Map<string, PacketResource[]> = new Map();

        for (const r of records) {
            if (r.packetType.type === PacketTypes.RRSIG || r.packetType.type === PacketTypes.EDNS) {
                continue;
            }

            const key = `${DnssecChain._normalize(r.name)}|${r.packetType.type}|${r.class}`;
            const bucket = out.get(key);

            if (bucket === undefined) {
                out.set(key, [r]);
            } else {
                bucket.push(r);
            }
        }

        return out;
    }

    /**
     * Filter every RRSIG out of the supplied records and hand them
     * back as a separate list — the symmetric companion to
     * `groupRrsets`.
     *
     * @param {PacketResource[]} records
     * @return {PacketResource[]}
     */
    public static rrsigs(records: PacketResource[]): PacketResource[] {
        return records.filter((r) => r.packetType.type === PacketTypes.RRSIG);
    }

    /**
     * Pull the DNSKEY records at `zone` out of a flat record list.
     *
     * @param {PacketResource[]} records
     * @param {string} zone
     * @return {PacketResource[]}
     */
    public static dnskeysAt(records: PacketResource[], zone: string): PacketResource[] {
        const target = DnssecChain._normalize(zone);
        return records.filter((r) =>
            r.packetType.type === PacketTypes.DNSKEY
            && DnssecChain._normalize(r.name) === target
        );
    }

    /**
     * @param {PacketResource[]} dnskeys
     * @return {DNSKEY[]}
     * @protected
     */
    protected static _zoneKeys(dnskeys: PacketResource[]): DNSKEY[] {
        const out: DNSKEY[] = [];

        for (const r of dnskeys) {
            if (!(r.packetType instanceof DNSKEY)) {
                continue;
            }

            // eslint-disable-next-line no-bitwise
            if ((r.packetType.flags & DnssecChain.ZONE_FLAG) === 0) {
                continue;
            }

            out.push(r.packetType);
        }

        return out;
    }

    /**
     * @param {string} name
     * @return {string}
     * @protected
     */
    protected static _normalize(name: string): string {
        if (name === '.' || name === '') {
            return '';
        }

        const stripped = name.endsWith('.') ? name.slice(0, -1) : name;
        return stripped.toLowerCase();
    }

}