import {DS} from '../Packet/Types/DS.js';

/**
 * One DNSSEC trust anchor — a `DS` record at a zone apex that anchors
 * the chain-of-trust the validator walks downward. The classical
 * configuration is a single anchor at the root (`.`) carrying the IANA
 * root KSK; deployments running RFC 8806 local roots or split-horizon
 * setups can add or replace anchors at any zone.
 */
export type TrustAnchor = {
    /**
     * FQDN of the zone the anchor signs (trailing dot or no — the
     * validator normalizes both forms). Use `.` for the root.
     */
    zone: string;

    /**
     * DS record fixing the parent's view of the zone's KSK: key tag,
     * algorithm, digest type, digest.
     */
    ds: DS;
};

/**
 * Bundled DNSSEC trust anchors + helpers.
 *
 * IANA publishes the root KSK as XML at
 * https://data.iana.org/root-anchors/root-anchors.xml and additionally
 * as the well-known fixture every recursor ships with. The current
 * production key is **KSK-2017** (key tag 20326, algorithm 8, digest
 * type 2, SHA-256 digest below) — published 2017-10-11, signing since
 * 2018-10-11. KSK-2024 is queued in the IANA pipeline; when it goes
 * live, deployments should refresh their bundle (and ideally pin both
 * keys during the rollover).
 *
 * @docs https://data.iana.org/root-anchors/root-anchors.xml
 * @docs https://datatracker.ietf.org/doc/html/rfc7958
 */
export class TrustAnchors {

    /**
     * IANA root KSK-2017 DS, as published in
     * https://data.iana.org/root-anchors/root-anchors.xml.
     *
     *  - KeyTag: 20326
     *  - Algorithm: 8 (RSA/SHA-256)
     *  - DigestType: 2 (SHA-256)
     *  - Digest: E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
     */
    public static readonly IANA_ROOT_KSK_2017: Readonly<TrustAnchor> = Object.freeze({
        zone: '.',
        ds: new DS(20326, 8, 2, 'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D')
    });

    /**
     * Default trust-anchor bundle. Currently a single entry — the IANA
     * root KSK-2017. Will gain KSK-2024 alongside once that key is
     * formally fielded; until then a single root anchor is correct.
     */
    public static readonly DEFAULT: ReadonlyArray<Readonly<TrustAnchor>> = Object.freeze([
        TrustAnchors.IANA_ROOT_KSK_2017
    ]);

    /**
     * Build a trust anchor from the kind of `(zone, DS)` pair a
     * resolver-config file would parse. The supplied `DS` is shallow-
     * copied into a fresh `Readonly<TrustAnchor>` so mutating the
     * argument afterwards does not leak into the validator's state.
     *
     * @param {string} zone
     * @param {DS} ds
     * @return {Readonly<TrustAnchor>}
     */
    public static of(zone: string, ds: DS): Readonly<TrustAnchor> {
        return Object.freeze({
            zone: zone,
            ds: new DS(ds.keyTag, ds.algorithm, ds.digestType, ds.digest)
        });
    }

    /**
     * Look up the most-specific anchor whose zone is an ancestor of
     * (or equal to) `name`. Used by the validator to find which anchor
     * an answer's signing zone descends from.
     *
     * Returns `undefined` when no anchor covers the name — the answer
     * is then "indeterminate" and a permissive validator passes it
     * through unverified.
     *
     * @param {ReadonlyArray<TrustAnchor>} anchors
     * @param {string} name
     * @return {TrustAnchor|undefined}
     */
    public static findFor(anchors: ReadonlyArray<TrustAnchor>, name: string): TrustAnchor | undefined {
        const all = TrustAnchors.findAllFor(anchors, name);
        return all.length === 0 ? undefined : all[0];
    }

    /**
     * Same closest-ancestor lookup as `findFor`, but returns every
     * anchor that ties for the deepest matching zone. RFC 5011 key
     * rollover overlap publishes multiple KSKs at the same zone for
     * up to the add-hold-down window; the validator needs to know
     * about all of them so a chain that signs against any one of
     * them is accepted.
     *
     * @param {ReadonlyArray<TrustAnchor>} anchors
     * @param {string} name
     * @return {TrustAnchor[]}
     */
    public static findAllFor(anchors: ReadonlyArray<TrustAnchor>, name: string): TrustAnchor[] {
        const target = TrustAnchors._normalize(name);
        const matches: TrustAnchor[] = [];
        let bestLabels = -1;

        for (const a of anchors) {
            const z = TrustAnchors._normalize(a.zone);

            if (z === '' || target === z || target.endsWith(`.${z}`)) {
                const labels = z === '' ? 0 : z.split('.').length;

                if (labels > bestLabels) {
                    matches.length = 0;
                    matches.push(a);
                    bestLabels = labels;
                } else if (labels === bestLabels) {
                    matches.push(a);
                }
            }
        }

        return matches;
    }

    /**
     * Lowercase + strip a trailing dot. Empty string is the canonical
     * form of the root zone.
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