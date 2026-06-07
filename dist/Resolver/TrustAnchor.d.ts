import { DS } from '../Packet/Types/DS.js';
export type TrustAnchor = {
    zone: string;
    ds: DS;
};
export declare class TrustAnchors {
    static readonly IANA_ROOT_KSK_2017: Readonly<TrustAnchor>;
    static readonly DEFAULT: ReadonlyArray<Readonly<TrustAnchor>>;
    static of(zone: string, ds: DS): Readonly<TrustAnchor>;
    static findFor(anchors: ReadonlyArray<TrustAnchor>, name: string): TrustAnchor | undefined;
    static findAllFor(anchors: ReadonlyArray<TrustAnchor>, name: string): TrustAnchor[];
    protected static _normalize(name: string): string;
}
