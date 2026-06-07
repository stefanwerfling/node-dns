import { DS } from '../Packet/Types/DS.js';
export class TrustAnchors {
    static IANA_ROOT_KSK_2017 = Object.freeze({
        zone: '.',
        ds: new DS(20326, 8, 2, 'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D')
    });
    static DEFAULT = Object.freeze([
        TrustAnchors.IANA_ROOT_KSK_2017
    ]);
    static of(zone, ds) {
        return Object.freeze({
            zone: zone,
            ds: new DS(ds.keyTag, ds.algorithm, ds.digestType, ds.digest)
        });
    }
    static findFor(anchors, name) {
        const all = TrustAnchors.findAllFor(anchors, name);
        return all.length === 0 ? undefined : all[0];
    }
    static findAllFor(anchors, name) {
        const target = TrustAnchors._normalize(name);
        const matches = [];
        let bestLabels = -1;
        for (const a of anchors) {
            const z = TrustAnchors._normalize(a.zone);
            if (z === '' || target === z || target.endsWith(`.${z}`)) {
                const labels = z === '' ? 0 : z.split('.').length;
                if (labels > bestLabels) {
                    matches.length = 0;
                    matches.push(a);
                    bestLabels = labels;
                }
                else if (labels === bestLabels) {
                    matches.push(a);
                }
            }
        }
        return matches;
    }
    static _normalize(name) {
        if (name === '.' || name === '') {
            return '';
        }
        const stripped = name.endsWith('.') ? name.slice(0, -1) : name;
        return stripped.toLowerCase();
    }
}
//# sourceMappingURL=TrustAnchor.js.map