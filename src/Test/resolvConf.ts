import assert from 'assert';
import {ResolvConf} from '../Lib/ResolvConf.js';
import {test} from './test.js';

test('ResolvConf#parse picks up nameservers in declaration order', () => {
    const r = ResolvConf.parse(`
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 2001:4860:4860::8888
`);
    assert.deepEqual(r.nameservers, ['8.8.8.8', '1.1.1.1', '2001:4860:4860::8888']);
});

test('ResolvConf#parse strips # and ; comments', () => {
    const r = ResolvConf.parse(`
# leading hash comment
nameserver 8.8.8.8 # inline comment
; semicolon comment
nameserver 1.1.1.1   ; another inline
`);
    assert.deepEqual(r.nameservers, ['8.8.8.8', '1.1.1.1']);
});

test('ResolvConf#parse blank lines are skipped', () => {
    const r = ResolvConf.parse('\n\n\nnameserver 8.8.8.8\n\n');
    assert.deepEqual(r.nameservers, ['8.8.8.8']);
});

test('ResolvConf#parse `search` overrides earlier search lines (last wins)', () => {
    const r = ResolvConf.parse(`
search foo.com bar.com
search baz.com
`);
    assert.deepEqual(r.search, ['baz.com']);
});

test('ResolvConf#parse keeps the legacy single `domain` directive', () => {
    const r = ResolvConf.parse('domain example.com\n');
    assert.equal(r.domain, 'example.com');
    assert.deepEqual(r.search, []);
});

test('ResolvConf#parse decodes well-known options key:value pairs', () => {
    const r = ResolvConf.parse('options ndots:2 timeout:3 attempts:5\n');
    assert.equal(r.options.ndots, 2);
    assert.equal(r.options.timeout, 3);
    assert.equal(r.options.attempts, 5);
});

test('ResolvConf#parse decodes bare-flag options', () => {
    const r = ResolvConf.parse('options rotate single-request edns0 trust-ad\n');
    assert.equal(r.options.rotate, true);
    assert.equal(r.options.singleRequest, true);
    assert.equal(r.options.edns0, true);
    assert.equal(r.options.trustAd, true);
});

test('ResolvConf#parse merges multiple `options` lines', () => {
    const r = ResolvConf.parse(`
options ndots:2
options rotate
`);
    assert.equal(r.options.ndots, 2);
    assert.equal(r.options.rotate, true);
});

test('ResolvConf#parse retains unknown options under .unknown', () => {
    const r = ResolvConf.parse('options custom-flag custom-pair:hello\n');
    assert.ok(r.options.unknown);
    assert.equal(r.options.unknown!['custom-flag'], true);
    assert.equal(r.options.unknown!['custom-pair'], 'hello');
});

test('ResolvConf#parse picks up `sortlist` entries verbatim', () => {
    const r = ResolvConf.parse('sortlist 130.155.160.0/255.255.240.0 130.155.0.0\n');
    assert.deepEqual(r.sortlist, ['130.155.160.0/255.255.240.0', '130.155.0.0']);
});

test('ResolvConf#parse silently skips unrecognized directives', () => {
    const r = ResolvConf.parse(`
foo bar baz
nameserver 8.8.8.8
random-keyword whatever
`);
    assert.deepEqual(r.nameservers, ['8.8.8.8']);
    assert.deepEqual(r.search, []);
});

test('ResolvConf#parse tolerates malformed key:value (uses fallback)', () => {
    const r = ResolvConf.parse('options ndots:abc timeout:\n');
    // Falls back to the resolver(5) default rather than throwing.
    assert.equal(r.options.ndots, 1);
    assert.equal(r.options.timeout, 5);
});

test('ResolvConf#parse is case-insensitive on directive names', () => {
    const r = ResolvConf.parse(`
NameServer 8.8.8.8
SEARCH foo.com
`);
    assert.deepEqual(r.nameservers, ['8.8.8.8']);
    assert.deepEqual(r.search, ['foo.com']);
});

test('ResolvConf#parse end-to-end: realistic /etc/resolv.conf', () => {
    const r = ResolvConf.parse(`
# /etc/resolv.conf — managed by NetworkManager
search corp.example.com home.example.com
nameserver 192.168.1.1
nameserver 8.8.8.8
options ndots:2 timeout:3 rotate edns0
`);
    assert.deepEqual(r.nameservers, ['192.168.1.1', '8.8.8.8']);
    assert.deepEqual(r.search, ['corp.example.com', 'home.example.com']);
    assert.equal(r.options.ndots, 2);
    assert.equal(r.options.timeout, 3);
    assert.equal(r.options.rotate, true);
    assert.equal(r.options.edns0, true);
});