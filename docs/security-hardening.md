# Security hardening — 0x20 and bailiwick

Two defenses against DNS spoofing and cache poisoning that should be on
every recursor's checklist. Both are small library helpers; one wires
into the existing clients via an option, the other is a building block
you call where it matters.

## 0x20 — query-name case randomization

DNS names are case-insensitive at the protocol level (RFC 1035 §2.3.3),
but the on-wire bytes are byte-for-byte preserved. A correct recursor
copies the question name verbatim into the response — case included.
Off-path attackers trying to spoof an answer have to guess the 16-bit
transaction ID, the source port, and now also the exact case pattern of
every letter in the name. With even modest names ("ExAmpLE.cOm" — 8
letters → 256 case patterns) that's another 8 bits of entropy at zero
cost.

This is RFC 5452 §9.2's recommendation; in operational circles it's
known as "the 0x20 hack" because flipping bit 0x20 in an ASCII letter
toggles its case.

### Turning it on

Pass `use0x20: true` to any client that supports it (UDPClient, TCPClient
— both wire-format clients). The client randomizes letter case in the
QNAME, sends the query, and on receive verifies the response question
name **byte-for-byte**. A mismatch raises:

```
Error: 0x20 mismatch: sent "ExaMpLe.cOm", got "example.com" — response may be spoofed
```

```ts
import {UDPClient, PacketTypes, PacketClass} from 'dns2ts';

const resolve = UDPClient.request({
  dns: '1.1.1.1',
  use0x20: true,
});

try {
  const response = await resolve('example.com', PacketTypes.A, PacketClass.IN);
  // response.questions[0].name is the scrambled form the server echoed back.
  console.log(response.answers);
} catch (err) {
  if (String(err).includes('0x20 mismatch')) {
    // Treat as untrusted — retry, fall back, log, alert.
  } else {
    throw err;
  }
}
```

The TCP-fallback path inherits the same option, so a UDP query with
`use0x20: true` that gets a TC bit set keeps the protection on the
retry.

### When to leave it off

Most modern recursors (Unbound, BIND, PowerDNS, Cloudflare 1.1.1.1,
Google 8.8.8.8) preserve case correctly. Some legacy or buggy recursors
normalize the name to lowercase in the response — in that case
`use0x20` would reject every response. Symptom: every query throws
`0x20 mismatch`. Fix: `use0x20: false` (the default) and move on.

It's safe to enable per-server: keep `use0x20: true` for a recursor you
trust to be correct, off for a known-broken one.

### Using the helper directly

If you implement a custom client or want to shape your own protocol on
top of `Packet`, the helper is exported:

```ts
import {Random0x20} from 'dns2ts';

const sent = Random0x20.scramble('example.com');     // e.g. 'ExaMpLe.cOm'
// … send query with QNAME = `sent` …
// … receive response …
if (!Random0x20.matches(sent, response.questions[0].name)) {
  throw new Error('possible spoofed response');
}
```

`scramble` only touches ASCII letters; digits, hyphens, dots, and IDN
punycode pass through unchanged. Randomness comes from the OS CSPRNG
(`crypto.randomBytes`), so it's safe against adversaries trying to
predict the case pattern.

## Bailiwick checks

A nameserver authoritative for `example.com` has authority over
`example.com` and its descendants — nothing else. The classic Kaminsky
2008 attack, and most cache-poisoning attacks since, exploited recursors
that accepted *any* record a server pushed into a response, including
records about unrelated zones. RFC 5452 §6 calls the proper defense
"in-bailiwick" filtering: discard records whose owner name lies outside
the responding server's zone of authority.

dns2ts ships a small helper for this. It's most useful for:

- A future recursive resolver in this library (the obvious user).
- Custom forwarders / proxies that take an upstream answer and re-emit
  it to clients.
- Cache implementations that store answers from untrusted recursors.

For a stub resolver pointing at a single trusted recursor (the typical
"resolve via 1.1.1.1" use case), bailiwick filtering is irrelevant —
you've already chosen to trust the recursor.

### `Bailiwick.contains(zone, name)`

The membership predicate. Case-insensitive, dot-tolerant.

```ts
import {Bailiwick} from 'dns2ts';

Bailiwick.contains('example.com',  'www.example.com');     // true
Bailiwick.contains('example.com',  'example.com');         // true
Bailiwick.contains('example.com',  'fakeexample.com');     // false (no '.' boundary)
Bailiwick.contains('example.com',  'com');                 // false (parent)
Bailiwick.contains('Example.COM.', 'WWW.EXAMPLE.com');     // true
Bailiwick.contains('.',            'anything.tld');        // true (root matches all)
```

### `Bailiwick.filter(packet, zone)`

Return a copy of `packet` with every answer / authority / additional
record whose owner name is outside `zone` removed. The question section
is untouched (it's your own question), and EDNS OPT records (owner name
"") are kept — bailiwick rules don't apply to EDNS pseudo-records.

```ts
import {Bailiwick} from 'dns2ts';

// In a forwarding / caching path, after fetching from an upstream server
// that's authoritative for `example.com`:
const trusted = Bailiwick.filter(upstreamResponse, 'example.com');
saveToCache(trusted);
```

This is opportunistic, not authoritative — a server that's authoritative
for `example.com` can still lie about `example.com` itself; the filter
only stops it from injecting records about *other* zones. Pair with
DNSSEC validation (when that lands) for actual answer authenticity.

### Putting bailiwick into a delegation walk

When a future recursive resolver here walks the delegation tree, the
canonical use is:

```ts
// Querying ns1.com. for example.com.'s NS records:
const response = await query('ns1.com.', 'example.com', PacketTypes.NS);

// `.com.` is the bailiwick of the .com nameservers we just asked.
const bw = Bailiwick.filter(response, 'com.');

// Now we can trust bw.authorities (NS records for example.com) and
// bw.additionals (glue) but not anything outside .com.
```

## Threat model recap

| Defense        | Mitigates                                       | Caveats                                  |
| -------------- | ----------------------------------------------- | ---------------------------------------- |
| Random ID      | Trivial off-path spoofing                       | Already on by default in all clients     |
| Random source port | Spoofing without per-port enumeration       | Node's UDP socket gets one automatically |
| **0x20**       | Off-path spoofing where ID and port are guessed | Some legacy recursors fail; opt-in       |
| **Bailiwick**  | Cache poisoning via out-of-zone records         | Doesn't authenticate the zone itself     |
| TSIG           | Tampering on a server-to-server channel         | Shared secret required ([guide](tsig.md))|
| DNSSEC         | Forged answers from any path                    | Not yet implemented                      |

The first two are infrastructure hygiene; 0x20 and bailiwick are the two
cheap-and-effective defenses on top. Once DNSSEC validation lands it
will be the strongest authentication, but in the meantime 0x20 +
bailiwick + TSIG + a trusted recursor is a defensible setup.

## Related

- [DNS clients](dns-clients.md) — where `use0x20` lives.
- [TSIG](tsig.md) — server-to-server authentication.
- [Reverse proxy](reverse-proxy.md) — additional rate limiting and
  filtering at the edge.