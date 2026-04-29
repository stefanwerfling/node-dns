# Response Rate Limiting (RRL)

DNS over UDP is the canonical reflection / amplification vector: a
spoofed query of ~50 bytes elicits a response of ~3 KiB, multiplying the
attacker's bandwidth roughly 60× toward an unwilling victim. Response
Rate Limiting (RRL, originally by Vixie & Schryver, deployed at scale
in BIND9) blunts this by capping how often the server answers similar
queries from a given client prefix.

dns2ts ships an opt-in RRL token bucket that you wire into `UDPServer`.

> **Only on UDP.** TCP/TLS/DoH cannot be source-spoofed in the same
> way — the connection establishment forces the attacker to receive
> the SYN-ACK / ServerHello, which is impossible behind a spoofed
> source. RRL on a connection-oriented transport just hurts legitimate
> bursty clients without buying anything.

## How it works

Every distinct `(client-prefix, qtype)` pair gets its own token bucket.
On each query the server tries to spend one token; if the bucket is
empty the server either drops the response (the standard RRL action)
or, every Nth over-budget query, sends back a header with `TC=1` set
(the "slip" mechanism). A client receiving a TC=1 response retries the
query over TCP, where source spoofing is much harder, so legitimate
clients can recover while spoofed-source amplification flows simply
disappear.

```ts
import {DnsServer, Rrl} from 'dns2ts';

const rrl = new Rrl({
  maxRate: 20,             // 20 responses/sec per (prefix, qtype)
  capacity: 50,            // burst budget — defaults to maxRate
  prefixV4Bits: 24,        // group by /24 IPv4
  prefixV6Bits: 56,        // group by /56 IPv6
  slipRatio: 2,            // every other over-budget query gets TC=1
  maxBuckets: 100_000,     // bound memory; FIFO eviction past this
});

const server = new DnsServer({
  udp: {rrl: rrl},
  handle: (request, send) => {
    // ... normal handler; only allowed queries reach this point
  },
});

server.on('rateLimited', (msg, rinfo, decision) => {
  // metric / log hook — `decision` is 'drop' or 'truncate'
  metrics.increment(`dns.rrl.${decision}`);
});

await server.listen();
```

## Picking parameters

- **`maxRate`**: the sustained allowed rate per bucket. Aim for a value
  comfortably above what any legitimate /24 generates in steady state
  but well below your authoritative server's outbound capacity divided
  by the number of buckets you expect to be active concurrently.
- **`capacity`**: the burst tolerance. `maxRate` is fine for most
  cases; set higher (e.g. `maxRate * 5`) if your traffic pattern is
  spiky.
- **`prefixV4Bits` / `prefixV6Bits`**: at /24 / /56 a single ISP
  customer or small organisation shares one bucket. Tighten (smaller
  prefix → wider grouping) if you see attackers rotating /32s within a
  /24; loosen (larger prefix) if you have legitimate distinct
  high-volume clients in the same /24.
- **`slipRatio`**: 0 = always drop, 1 = always truncate, 2 (default) =
  every other. The default is the BIND9 setting and is a good
  compromise between "let real clients recover" and "don't reflect
  half the spoofed flood".
- **`maxBuckets`**: how many buckets you're willing to keep in memory.
  Each bucket is a tiny object (≈64 bytes); 100 000 ≈ 6 MiB. FIFO
  eviction kicks in when you exceed this — the oldest bucket goes,
  which means a client that returns after a long quiet period gets a
  fresh budget, which is the desired behavior anyway.

## Direct API

`Rrl.check(clientIp, qtype, now?)` returns one of `'allow' | 'drop' |
'truncate'` and is the only method you usually need. `now` is epoch
milliseconds and exists for testing — production code should rely on
the default `Date.now()`.

```ts
const rrl = new Rrl({maxRate: 5});

rrl.check('192.0.2.1', 1);           // → 'allow'
rrl.check('192.0.2.1', 1);           // → 'allow'
rrl.check('192.0.2.1', 1);           // ... up to capacity
rrl.check('192.0.2.1', 1);           // → 'drop' or 'truncate'

rrl.size();                          // current bucket count
rrl.reset();                         // clear all state — for tests
```

`check` throws on malformed IP input; the wired-up UDPServer relies on
Node's `dgram.RemoteInfo.address` which is always a valid IPv4 or IPv6
string, so this only matters for direct API users.

## What RRL does **not** do

- **Per-query cost limiting**: RRL counts responses, not response
  size. A torrent of large ANY queries is rate-limited the same as a
  torrent of small A queries. Pair with response-size policies (e.g.
  refuse ANY, or strip oversized answers) for full amplification
  defense.
- **Recursive resolver protection**: RRL is for authoritative servers.
  Recursive resolvers facing the open internet should also rate-limit,
  but the threat model and parameters are different — generally you
  want per-client limits, not per-prefix.
- **DDoS protection at the link layer**: RRL stops the server from
  participating in amplification, not from being saturated by raw
  query volume. Combine with edge filtering / scrubbing for that.

## Related

- [Security hardening](security-hardening.md) — the broader threat
  model and other defenses.
- [DNS servers](dns-servers.md) — server configuration overview.
- RFC 5358 — Preventing Use of Recursive Nameservers in Reflector
  Attacks.