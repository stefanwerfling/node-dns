import assert from 'assert';
import { DS } from '../Packet/Types/DS.js';
import { TrustAnchors } from '../Resolver/TrustAnchor.js';
import { test } from './test.js';
test('TrustAnchors#IANA_ROOT_KSK_2017 carries the published key tag and digest', () => {
    const anchor = TrustAnchors.IANA_ROOT_KSK_2017;
    assert.equal(anchor.zone, '.');
    assert.equal(anchor.ds.keyTag, 20326);
    assert.equal(anchor.ds.algorithm, 8);
    assert.equal(anchor.ds.digestType, 2);
    assert.equal(anchor.ds.digest.toUpperCase(), 'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D');
});
test('TrustAnchors#DEFAULT contains exactly the root KSK', () => {
    assert.equal(TrustAnchors.DEFAULT.length, 1);
    assert.strictEqual(TrustAnchors.DEFAULT[0], TrustAnchors.IANA_ROOT_KSK_2017);
});
test('TrustAnchors#of detaches the DS so caller mutations do not leak', () => {
    const ds = new DS(1, 8, 2, 'aabbcc');
    const anchor = TrustAnchors.of('example.com.', ds);
    ds.keyTag = 99;
    assert.equal(anchor.ds.keyTag, 1);
});
test('TrustAnchors#findFor returns the root anchor for any name', () => {
    const anchors = [TrustAnchors.IANA_ROOT_KSK_2017];
    assert.strictEqual(TrustAnchors.findFor(anchors, 'www.example.com'), anchors[0]);
    assert.strictEqual(TrustAnchors.findFor(anchors, '.'), anchors[0]);
});
test('TrustAnchors#findFor picks the most-specific ancestor anchor', () => {
    const root = TrustAnchors.IANA_ROOT_KSK_2017;
    const tld = TrustAnchors.of('com.', new DS(2, 8, 2, 'deadbeef'));
    const apex = TrustAnchors.of('example.com.', new DS(3, 8, 2, 'cafebabe'));
    const anchors = [root, tld, apex];
    assert.strictEqual(TrustAnchors.findFor(anchors, 'www.example.com'), apex);
    assert.strictEqual(TrustAnchors.findFor(anchors, 'mail.example.org'), root);
    assert.strictEqual(TrustAnchors.findFor(anchors, 'foo.com'), tld);
});
test('TrustAnchors#findFor returns undefined when no anchor covers the name', () => {
    const apex = TrustAnchors.of('example.com.', new DS(1, 8, 2, 'aabbcc'));
    assert.equal(TrustAnchors.findFor([apex], 'www.example.org'), undefined);
});
test('TrustAnchors#findFor case-insensitive and trailing-dot tolerant', () => {
    const apex = TrustAnchors.of('Example.COM.', new DS(1, 8, 2, 'aabbcc'));
    assert.strictEqual(TrustAnchors.findFor([apex], 'WWW.example.com'), apex);
    assert.strictEqual(TrustAnchors.findFor([apex], 'www.example.com.'), apex);
});
//# sourceMappingURL=trustAnchor.js.map