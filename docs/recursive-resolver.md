# Recursive resolver

Iterative recursive resolver: starts at the root, follows NS referrals
downward, follows CNAME chains, caches every observed RRset, and
returns a recursive-style response to the caller. Uses Node's built-in
`dgram` for the default UDP transport — no extra dependencies.

The implementation lives in `src/Resolver/`:

- `DnsCache` — TTL-aware RRset cache (positive + negative per RFC 2308)
- `RootHints` — bundled IANA root servers + cache priming
- `RecursiveResolver` — the iterative engine

## Quick start

```ts
import {RecursiveResolver, PacketTypes} from 'dns2ts';

const resolver = new RecursiveResolver();

const response = await resolver.resolve('www.example.com', PacketTypes.A);

console.log(response.header.rcode);     // 0 = NOERROR
console.log(response.answers);          // [PacketResource …]
```

The first call walks root → `.com` → `example.com` and caches every
RRset it sees. Subsequent calls for the same name are cache hits. Calls
for *related* names (e.g. `mail.example.com`) reuse the delegation chain
and skip back to the lowest cached delegation point — typically just one
upstream query for the leaf record.

## Cache (`DnsCache`)

`DnsCache` is keyed by `(name, type, class)`. Lookups are
case-insensitive and trailing-dot-tolerant (DNS names are
case-insensitive at the protocol level, RFC 1035 §2.3.3).

```ts
import {DnsCache, PacketClass, PacketTypes} from 'dns2ts';

const cache = new DnsCache({
  maxEntries: 50_000,        // LRU cap (default 10 000)
  maxTtlSeconds: 86_400,     // RFC 8767 ceiling (default 1 day)
  minTtlSeconds: 5,          // floor for TTL=0 responses (default 0)
  maxStaleSeconds: 86_400,   // RFC 8767 serve-stale window (default 0 = off)
});

cache.get('www.example.com', PacketTypes.A, PacketClass.IN);
// → DnsCacheEntry | null
```

Entries carry an `rcode` field that distinguishes positive
(`'NOERROR'`) from negative (`'NXDOMAIN'`, `'NODATA'`) cache hits — the
resolver synthesizes the right response shape on hit.

## Root hints (`RootHints`)

The 13 IANA roots are bundled as `RootHints.DEFAULT`. The list rarely
changes (most recently `b.root-servers.net` IPv4 in 2023); for
deployments that want to track upstream directly, parse a `named.root`
file.

```ts
import {RootHints} from 'dns2ts';

// Use the bundled list (default)
new RecursiveResolver();

// Parse the canonical hints file at startup
import {readFileSync} from 'fs';
const text = readFileSync('/etc/dns/named.root', 'utf8');
new RecursiveResolver({rootHints: RootHints.fromNamedRoot(text)});

// Custom split-horizon roots (RFC 8806 local roots)
new RecursiveResolver({rootHints: [
  {name: 'a.local-root.', ipv4: '10.0.0.1'},
  {name: 'b.local-root.', ipv4: '10.0.0.2'},
]});
```

`RootHints.toRecords` returns ready-to-cache NS + A/AAAA records.
`RootHints.seedCache(cache, servers?)` is what the resolver constructor
calls; you can call it again after key roll to refresh.

## Configuration

```ts
new RecursiveResolver({
  cache: myCache,             // share a cache across resolvers
  rootHints: customList,
  transport: myTransport,     // see "Custom transports" below
  use0x20: true,              // RFC 5452 §9.2 case randomization (default true)

  // Per-resolution defaults — overridable via resolve(... , {...})
  timeoutMs: 10_000,          // wallclock budget for one resolve()
  queryTimeoutMs: 2_000,      // per-upstream-query timeout
  maxQueries: 50,             // upstream queries before giving up
  maxCnameDepth: 16,          // CNAME hops before giving up

  port: 53,                   // upstream UDP port

  // RFC 7766 §5 TCP fallback — see "Truncation" below
  tcpFallback: true,          // retry over TCP on TC=1 (default true)
  tcpPort: 53,                // upstream TCP port
  tcpTransport: myTcp,        // injectable, default = Node `net` one-shot

  // RFC 6891 EDNS(0) — see "EDNS buffer negotiation" below
  useEdns: true,              // append OPT to outgoing queries (default true)
  udpPayloadSize: 4096,       // advertised buffer (default 4096)
});
```

`resolve(qname, qtype, options?)` accepts the same budget keys to
override per-call:

```ts
await resolver.resolve('www.example.com', PacketTypes.A, {
  timeoutMs: 2000,             // tight budget for a stub-style query
});
```

## Response shape

The returned `Packet` looks like a recursive-server reply:

| Header field | Value |
| ------------ | ----- |
| `qr`         | `1`   |
| `ra`         | `1`   |
| `aa`         | `0`   |
| `rcode`      | `NOERROR` (0), `NXDOMAIN` (3), or `SERVFAIL` (2) |
| `questions`  | one entry, mirroring the original `(qname, qtype, qclass)` |
| `answers`    | followed CNAME chain + final RRset |
| `authorities`| SOA on negative answers (RFC 2308) |

The `RCODE` constant exports the standard codes:

```ts
import {RCODE} from 'dns2ts';

if (response.header.rcode === RCODE.NXDOMAIN) {
  /* ... */
}
```

## Spoofing defenses

The resolver applies all the off-path mitigations the building blocks
in `Lib/` provide:

- Random 16-bit transaction ID per query, verified on the response.
- **Bailiwick filtering** (`Lib/Bailiwick`, RFC 5452 §6) — every
  response is filtered against the responding server's zone before
  records reach the cache, so a TLD server can't poison records for a
  sibling zone. The filter is keyed on the *server's* zone, so the
  root (zone `.`) can validly ship glue for any name; lower-tier
  servers are restricted to their own bailiwick.
- **0x20 case randomization** (`Lib/Random0x20`, RFC 5452 §9.2) — QNAME
  case is scrambled before sending and the response's question section
  is checked case-sensitively. Mismatch → reject.
- Per-`(server, qname, qtype)` loop guard prevents query cycles.
- `maxQueries` + `timeoutMs` cap the worst-case work for misbehaved
  zones.

What the resolver does **not** do (yet):

- **Prefetch.** Entries are not refreshed proactively before they
  expire — only on the first access after expiry (when serve-stale
  is enabled).

## Truncation (RFC 7766 §5)

When an upstream replies with `TC=1` (response too large for UDP) the
resolver reissues the same question over TCP via `tcpTransport`
(default: a one-shot length-prefixed connection over Node `net`). The
retry counts as a separate query against `maxQueries` and runs under
the remaining `timeoutMs` window — so a poorly-behaved upstream that
truncates everything still hits the budget cap.

```ts
new RecursiveResolver({
  tcpFallback: true,                // default
  tcpPort: 53,                      // default
  tcpTransport: async (ip, port, query) => {
    /* custom TCP transport — same shape as `transport` */
  },
});

// Opt out (truncated responses are passed through unmodified):
new RecursiveResolver({tcpFallback: false});
```

Failures of the TCP retry (timeout, connection refused, parse error)
propagate up and surface as `SERVFAIL` to the caller. There is no
TCP-side connection pooling in v1 — every retry opens a fresh socket.

## EDNS buffer negotiation (RFC 6891)

By default each outgoing query carries an EDNS(0) `OPT` RR advertising
the resolver's UDP buffer size (default 4096). Most authoritative
servers honour the advertised size and reply over UDP without
truncation, cutting one TCP roundtrip for medium-size answers (DNSSEC
chains, multi-record A/AAAA RRsets).

```ts
new RecursiveResolver({
  useEdns: true,             // default
  udpPayloadSize: 4096,      // common BIND/Unbound default

  // The DNS Flag Day 2020 recommendation — fits IPv6+UDP+IPsec
  // headroom inside a 1500-byte PMTU. Use this if you suspect
  // PMTU-blackhole networks between you and authoritative auths.
  // udpPayloadSize: 1232,
});

// Suppress the OPT entirely (some firewalls eat EDNS) — auths fall
// back to the legacy 512-byte UDP ceiling and the resolver leans on
// the TCP retry path.
new RecursiveResolver({useEdns: false});
```

When `dnssec` is enabled, the OPT also carries the DO (DNSSEC OK) bit
(RFC 3225) so the upstream includes RRSIG / NSEC / NSEC3 records — the
validator would otherwise see no signatures and reject every signed
answer as bogus. The DO bit is cleared automatically when `dnssec` is
disabled.

When a server's response carries an OPT whose advertised payload size
(RFC 6891 §6.1.2 — the OPT RR's CLASS field) is *smaller* than the
configured `udpPayloadSize`, the resolver remembers it per-server and
downgrades subsequent queries to that server. The buffer is only
ratcheted *down*, never up — a server claiming 8 KiB will not push
us past our configured ceiling. This is what RFC 6891 §6.2.3 expects:
"the requestor MAY assume the responder's maximum payload size in
follow-up queries".

## DNSSEC validation (opt-in)

Enable DNSSEC validation by passing `dnssec: true` (uses bundled IANA
trust anchors and `permissive` mode), or an object for finer control:

```ts
import {RecursiveResolver, TrustAnchors} from 'dns2ts';

const resolver = new RecursiveResolver({
  dnssec: {
    trustAnchors: TrustAnchors.DEFAULT,    // bundled IANA root KSK-2017
    mode: 'permissive',                    // 'strict' fails closed on insecure
  },
});

const r = await resolver.resolve('www.example.com', PacketTypes.A);

// AD bit lives at bit 1 of the legacy 3-bit Z field (RFC 4035 §3.2):
//   header.z == 0b010 → AD set
//   header.z == 0b000 → AD clear
const ad = (r.header.z & 0b010) >> 1;
```

**How it works:**

1. After a successful authoritative answer, `_dnssecFinalize` is called
   with the **raw** response (RRSIG records intact — the built response
   has them filtered out).
2. `_authenticateZone` walks the chain top-down from a configured
   trust anchor (default: IANA root KSK-2017) down to the answer's
   signing zone:
   - Fetch DNSKEY of each zone, validate against parent's DS via
     `DnssecChain.validateDnskeyRrset`
   - Fetch DS of next-deeper zone *from the parent* (RFC 4035 §5.2 —
     `_queryDsAtParent` bypasses normal NS-chasing)
   - Validate DS RRset against current zone's DNSKEYs. **Insecure
     delegations** (parent NOERRORs with no DS records) must arrive
     with a valid NSEC or NSEC3 proof — `_verifyInsecureDelegationProof`
     authenticates the NSEC/NSEC3 RRsets against the parent's DNSKEYs
     and runs `NegativeProof.verifyInsecureDelegationNsec` /
     `verifyInsecureDelegationNsec3` (the latter honours the RFC 5155
     §6 opt-out flag — large parent zones use opt-out NSEC3 to avoid
     enumerating every unsigned child). A claim of "no DS" without a
     verifying proof is rejected as **bogus** so an off-path attacker
     can't downgrade signed zones by stripping records.
3. Validate every RRset in the answer against the authenticated
   DNSKEYs via `DnssecChain.validateRrset`.
4. For NXDOMAIN/NODATA: validate the NSEC or NSEC3 proof via
   `NegativeProof.verifyNxdomainNsec`/`verifyNxdomainNsec3` etc.
5. Result:
   - `secure` → set AD bit
   - `bogus` → return SERVFAIL (RFC 4035 §5.5)
   - `insecure` → pass through with AD=0 (or SERVFAIL in strict mode)
   - `indeterminate` (no anchor covers zone) → pass through with AD=0

**Custom trust anchors:**

```ts
import {TrustAnchors, DS} from 'dns2ts';

// e.g., a private island root running its own DNSSEC
const anchor = TrustAnchors.of('local-root.', new DS(/* keyTag */ 12345,
                                                       /* algo */ 8,
                                                       /* digestType */ 2,
                                                       'aabbcc...'));

new RecursiveResolver({dnssec: {trustAnchors: [anchor]}});
```

**Strict mode** (no insecure passthrough):

```ts
new RecursiveResolver({dnssec: {mode: 'strict'}});
// Insecure delegations (no DS at parent) → SERVFAIL
```

**The exposed primitives** (`TrustAnchors`, `DnssecChain`,
`NegativeProof`) are also useful standalone — e.g. validating a
recorded response in a test, or composing proofs without running an
iterative resolver.

## Custom transports

The transport is `(serverIp, port, query) => Promise<Packet>`. Useful
for:

- **Tests** — drive deterministic referral chains without real DNS
  servers.
- **Forwarding mode** — wrap an upstream resolver instead of querying
  the auths directly.
- **Metrics / tracing** — wrap the default transport to record
  per-server latency.

```ts
import {RecursiveResolver, Packet} from 'dns2ts';

const resolver = new RecursiveResolver({
  transport: async (ip, port, query) => {
    const start = Date.now();
    const response = await defaultUdp(ip, port, query);
    metrics.recordLatency(ip, Date.now() - start);
    return response;
  },
});
```

## Serve-stale (RFC 8767)

Configure the underlying cache with `maxStaleSeconds > 0` to enable
serve-stale: when an entry is past its TTL but still inside the stale
window, the resolver returns the stale answer to the current request
*and* fires an asynchronous refresh in the background. The next caller
sees the fresh data.

```ts
import {DnsCache, RecursiveResolver} from 'dns2ts';

const resolver = new RecursiveResolver({
  cache: new DnsCache({maxStaleSeconds: 86_400}), // 1-day stale window
});
```

The refresh runs through the full iterative loop (with `bypassCache`
internally so it doesn't immediately return the stale entry it's
meant to replace), populates the cache via the normal cache-write
path, and silently swallows any upstream error — the caller has
already received the stale answer and a transient upstream failure
should not surface.

Concurrent stale hits dedupe via an in-flight set keyed by
`(qname, qtype, qclass)`, so the second of two near-simultaneous
stale lookups doesn't kick off a duplicate refresh (RFC 8767 §6
calls out the stampede risk explicitly).

`maxStaleSeconds: 0` (the default) disables serve-stale — expired
entries are dropped and the next caller waits on a fresh resolution.

## Negative caching (RFC 2308)

NXDOMAIN and NODATA answers are cached with TTL =
`min(SOA.MINIMUM, SOA.TTL)` — exactly what RFC 2308 §5 specifies. A
second query for the same name within the negative TTL is served from
cache, no upstream traffic.

```ts
await resolver.resolve('absent.example.com', PacketTypes.A);
// cache now carries an NXDOMAIN entry; the SOA in the authority
// section's MINIMUM controls how long it lives.

await resolver.resolve('absent.example.com', PacketTypes.A);
// served from cache, no upstream query.
```

## Testing your code

For unit tests, share a cache or pass a mock transport:

```ts
import {DnsCache, RecursiveResolver, PacketClass, PacketResource,
        PacketTypes, A} from 'dns2ts';

const cache = new DnsCache();
cache.set('www.example.com', PacketTypes.A, PacketClass.IN, [
  new PacketResource('www.example.com',
                     new A('192.0.2.1'),
                     PacketClass.IN, 60),
], 60);

const resolver = new RecursiveResolver({cache: cache});
// Now `await resolver.resolve('www.example.com', PacketTypes.A)`
// returns the pre-seeded record without any network access.
```

The resolver's own test suite uses an injectable transport
(`MockTransport` in `Test/recursiveResolver.ts`) to exercise referral
chains, NXDOMAIN, NODATA, CNAME chains, glueless delegation, bailiwick
filtering, 0x20 verification, and budget enforcement — all without
opening a socket. Worth a look as a template for application-level
tests.

## System resolver configuration

The library ships a small `ResolvConf` parser for `/etc/resolv.conf`-
format files. It's a utility for callers that want to bootstrap a
forwarding setup from the host's system resolver settings — the
recursive resolver itself doesn't read it.

```ts
import {ResolvConf} from 'dns2ts';

// Parse the system file (Linux/BSD).
const conf = ResolvConf.fromFile();           // defaults to /etc/resolv.conf

// Or feed an explicit string (tests, embedded configs).
const conf2 = ResolvConf.parse(`
search corp.example.com
nameserver 192.168.1.1
options ndots:2 timeout:3
`);

console.log(conf.nameservers);   // ['192.168.1.1', ...]
console.log(conf.search);        // ['corp.example.com', ...]
console.log(conf.options.ndots); // 2
```

The parser is tolerant: unknown directives are skipped silently, and
unknown `options` tokens land in `options.unknown` so callers don't
lose information. Last-write-wins for `search` per resolver(5) §3,
malformed numeric options fall back to resolver(5) defaults.

## Related

- [Security hardening](security-hardening.md) — Bailiwick + 0x20 are
  primitives the resolver builds on.
- [DNSSEC](dnssec.md) — the validator primitives the v2 resolver will
  plug into the response path.
- [DNS clients](dns-clients.md) — `UDPClient`/`TCPClient` are the
  forwarding-style alternative when you want to send to an upstream
  recursor instead of running iterative resolution yourself.