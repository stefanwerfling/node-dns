# Stub resolver

`StubResolver` adds resolver(5) / glibc-style **search-path expansion**
to any existing transport. It does no networking on its own — you
hand it a backend resolver function and it sequences calls per the
classic short-name / `ndots` rules.

This is the layer between "raw DNS query" and "host name in a config
file". A user typing `ssh server` expects `server.corp.local` to be
tried via the configured search domains; `StubResolver` is the piece
that makes that happen.

## One-line setup — `SystemResolver`

For the common case — read `/etc/resolv.conf` + `/etc/hosts`, build
the full pipeline, return a resolver — `SystemResolver.system()` is
a single call:

```ts
import {SystemResolver, PacketTypes} from 'dns2ts';

const resolver = SystemResolver.system();
const response = await resolver.resolve('host', PacketTypes.A);
```

The pipeline it assembles, top to bottom:

1. **`StubResolver`** — search-path / `ndots` expansion
2. **`HostsFile`** — `/etc/hosts` first; NODATA halts, miss falls through
3. **`FailoverBackend`** — multi-nameserver retry / rotation per
   `options.timeout` / `options.attempts` / `options.rotate`
4. **`UDPClient`** per nameserver — RFC 7766 §8 TC fallback baked in

Override the per-server transport via the `backend` option (the same
`FailoverBackendBuilder` shape used by `FailoverBackend.fromConfig`):

```ts
import {SystemResolver, TCPClient, ClientOptionsProtocol} from 'dns2ts';

const resolver = SystemResolver.system({
  backend: ({host, port}) => TCPClient.request({
    dns: host,
    port: port ?? 853,
    protocol: ClientOptionsProtocol.tls,
  }),
});
```

Other knobs:
- `resolvConfPath` / `hostsPath` for non-standard locations
- `skipHosts: true` to bypass the hosts-file layer entirely
- `shouldFailover` to override the BIND/glibc default failover predicate
- `cache` to enable an in-memory response cache between the stub and
  the upstream — see [Response caching](#response-caching) below
- `SystemResolver.hasSystemFiles({...})` reports which files exist
  before you call `system()`

`resolver.stub` exposes the wrapped `StubResolver` so callers can
inspect `expand()`, `search`, `ndots` without unwrapping the layers;
`resolver.cache` returns the `DnsCache` instance (or `null` when
caching is disabled) for instrumentation, `clear()` on config reload,
or pre-population.

## Response caching

By default `SystemResolver` is a pure forwarder — every query goes to
the network. For latency-sensitive workloads or `dig`-style scripts
that re-query the same names, opt in to caching by setting `cache`:

```ts
import {SystemResolver, PacketTypes} from 'dns2ts';

// Defaults: 10000 entries, 1-day max TTL, RFC 2308 negative caching.
const resolver = SystemResolver.system({cache: true});
```

The cache sits *between* the hosts-file layer and the upstream — so
`/etc/hosts` stays authoritative for local names (and never consumes
cache slots), and only real network answers are cached.

Tune via `DnsCacheOptions`:

```ts
const resolver = SystemResolver.system({
  cache: {
    maxEntries: 5000,
    maxTtlSeconds: 600,        // cap upstream TTLs at 10 min
    minTtlSeconds: 5,          // pin sub-5s TTLs to 5s
    maxStaleSeconds: 3600,     // RFC 8767 serve-stale window
    prefetchThreshold: 0.1,    // BIND-style prefetch at 10% TTL left
  },
});
```

Pass an external `DnsCache` instance to share state across multiple
resolvers (e.g. a per-service stub and a per-host stub backed by the
same hot cache):

```ts
import {DnsCache, SystemResolver} from 'dns2ts';

const shared = new DnsCache({maxEntries: 50_000});
const resolverA = SystemResolver.system({cache: shared});
const resolverB = SystemResolver.system({cache: shared, /* different backend */});
```

What gets cached:

- **`NOERROR`** with answers → positive cache, TTL = min TTL across
  the answer section (RFC 1035 §3.7)
- **`NXDOMAIN`** → negative cache, TTL = `min(SOA.MINIMUM, SOA.TTL)`
  from the authority section (RFC 2308 §5)
- **`NOERROR`** with empty answers (NODATA) → same negative-caching
  shape as NXDOMAIN
- **`SERVFAIL` / `REFUSED` / `FORMERR` / `NOTIMP`** are **not** cached
  — pinning a transient failure would mask recovery. Override via the
  lower-level `CachedStubBackend({isCacheable})` if your upstream's
  failure semantics are sticky.

Stale-while-revalidate (RFC 8767) and BIND-style prefetch are
inherited from the underlying `DnsCache` — pass `maxStaleSeconds` and
`prefetchThreshold` and the wrapper will return the cached answer
immediately while firing an asynchronous refresh in the background
(deduped per `(qname, qtype, qclass)`).

The same wrapper is exposed standalone as `CachedStubBackend` for
hand-composed pipelines:

```ts
import {CachedStubBackend, StubResolver, UDPClient, ResolvConf} from 'dns2ts';

const conf = ResolvConf.fromFile();
const upstream = UDPClient.request({dns: conf.nameservers[0]});
const cached = new CachedStubBackend(upstream, {
  cacheOptions: {maxEntries: 5000, maxStaleSeconds: 3600},
});
const stub = StubResolver.fromConfig(conf, cached.resolve);
```

The rest of this doc covers the lower-level pieces — useful when you
want to compose them by hand, swap in a recursive resolver,
DoT/DoH transport, in-memory caching, etc.

## Quick start

```ts
import {
  ResolvConf,
  StubResolver,
  UDPClient,
  PacketTypes,
} from 'dns2ts';

const conf = ResolvConf.fromFile();   // /etc/resolv.conf

// Backend: forward each candidate to the first nameserver.
const upstream = UDPClient.request({dns: conf.nameservers[0]});

const stub = StubResolver.fromConfig(conf, upstream);

// "server" is short — stub expands it to "server.<each search>" before
// falling back to the bare name. First non-NXDOMAIN response wins.
const response = await stub.resolve('server', PacketTypes.A);
console.log(response.questions[0].name);   // e.g. "server.corp.local"
```

## Expansion rules

`stub.expand(name)` returns the ordered FQDN list the resolver will
try. The semantics match resolver(5) / glibc:

| Input shape                       | Order tried                                  |
| --------------------------------- | -------------------------------------------- |
| `host.` (trailing dot)            | `[host]` — absolute, **no search expansion** |
| `host` with dots ≥ `ndots`        | `[host, host.<search0>, host.<search1>, …]`  |
| `host` with dots `<` `ndots`      | `[host.<search0>, …, host]`                  |
| `host` with empty search list     | `[host]`                                     |
| `ndots: 0`                        | `[host]` — search expansion disabled         |

Default `ndots: 1` puts every dotless single-label name onto the
"short" branch — which is what most people expect: typing `server`
walks the search list, typing `server.example.com` doesn't.

## Fall-through semantics

The stub walks candidates one at a time and stops at the first
non-NXDOMAIN response:

- **NXDOMAIN** advances to the next candidate.
- **NOERROR** (with or without answers) is returned immediately. A
  NOERROR-with-empty-answer (NODATA) means "this FQDN exists, just
  not for the requested type" — that's a definitive answer, not a
  hint to keep searching.
- **SERVFAIL / REFUSED / FORMERR / NOTIMP** are returned immediately.
  Silently advancing past these would mask real upstream failures.
- If every candidate returns NXDOMAIN, the **last** response is
  returned (preserves the negative-caching SOA the auth supplied for
  the longest candidate).

## Composition

The backend is just a function:

```ts
type StubResolverBackend = (
  name: string,
  type: PacketTypes | number,
  cls: PacketClass | number,
) => Promise<Packet>;
```

Anything that fits this shape works. Common choices:

```ts
// Plain UDP forwarder
const backend = UDPClient.request({dns: '1.1.1.1'});

// DoT
const backend = TCPClient.request({
  dns: 'dns.google',
  protocol: ClientOptionsProtocol.tls,
});

// Recursive resolver
const recursive = new RecursiveResolver();
const backend: StubResolverBackend = (n, t, c) => recursive.resolve(n, t, c);

// Custom — try multiple nameservers in parallel, etc.
const backend: StubResolverBackend = async (name, type, cls) => {
  // your own logic
};
```

The stub itself is stateless beyond `(search, ndots, resolver)`. To
re-read `/etc/resolv.conf` after a change, build a new stub.

## API

```ts
new StubResolver({
  resolver: backend,
  search: ['example.com', 'corp.local'],
  ndots: 1,
});

// or from a parsed /etc/resolv.conf
StubResolver.fromConfig(parsedResolvConf, backend);

// methods
stub.resolve(name, type, cls?): Promise<Packet>;
stub.expand(name): string[];

// getters
stub.search;   // copy of the current search list
stub.ndots;    // current ndots threshold
```

`StubResolver.fromConfig` honours the legacy `domain` directive:
when `parsed.search` is empty, `[parsed.domain]` is used as a
single-entry search list (matching resolver(5) §2 fallback).

## Multi-nameserver failover — `FailoverBackend`

`FailoverBackend.combine(backends, options)` composes N backends into
one with the resolver(5) retry / rotation semantics. Designed to slot
between the per-server transport (`UDPClient`, `TCPClient`, …) and
the search-path layer above it:

```ts
import {
  ResolvConf, StubResolver, FailoverBackend, UDPClient, PacketTypes,
} from 'dns2ts';

const conf = ResolvConf.fromFile();

const backend = FailoverBackend.fromConfig(conf, ({host, port}) =>
  UDPClient.request({dns: host, port: port}));

if (backend === null) {
  throw new Error('no nameservers configured');
}

const stub = StubResolver.fromConfig(conf, backend);
await stub.resolve('host', PacketTypes.A);
```

`FailoverBackend.fromConfig` reads from the parsed resolv.conf:

| resolv.conf option | Meaning                                       |
| ------------------ | --------------------------------------------- |
| `nameserver` lines | One backend each, in declaration order        |
| `options.timeout`  | Per-attempt timeout (seconds → ms)            |
| `options.attempts` | Retries per backend before moving on          |
| `options.rotate`   | Round-robin the starting backend across calls |

It returns `null` when `parsed.nameservers` is empty — the caller
decides what to do (fall back to public DNS, throw, etc.).

### Failover predicate

The default predicate matches glibc / BIND:

- **Thrown error** (timeout, ECONNREFUSED, parse failure) → fail over
- **`SERVFAIL`** → fail over
- **`NXDOMAIN` / `NOERROR` / `REFUSED` / `FORMERR` / `NOTIMP`** →
  return verbatim, don't retry

Override via `options.shouldFailover` — a typical BIND-behind-ACL
setup also fails over on `REFUSED`:

```ts
import {FailoverBackend, RCODE} from 'dns2ts';

const backend = FailoverBackend.combine(backends, {
  attempts: 3,
  shouldFailover: (r) => {
    if (r instanceof Error) return true;
    return r.header.rcode === RCODE.SERVFAIL ||
           r.header.rcode === RCODE.REFUSED;
  },
});
```

### Order of retry

For each call, the wrapper walks `(server × attempt)` tuples until
one returns a non-failover outcome:

1. server[start], attempt 1 → 2 → … → N
2. server[start+1], attempt 1 → …
3. …through every backend

`start` is `0` by default; with `rotate: true` it advances per call
(mod backend count). If every tuple fails over, the **last** outcome
surfaces — so a final SERVFAIL or thrown error reaches the caller and
`StubResolver` halts the search list as it would on any single-backend
SERVFAIL.

## Out of scope

- **Parallel fan-out** of upstreams (every backend simultaneously,
  first non-failover wins). resolver(5) is sequential by design; build
  fan-out on top of `StubResolverBackend` if you need it.
- **Per-server health tracking** — every call starts fresh, no
  circuit breakers. A consistently failing backend just costs the
  configured timeout per call.
- **Caching** — every `resolve()` call invokes the backend for each
  candidate. Use `DnsCache` (or any cache the backend already
  provides) when latency matters.

## `/etc/hosts` integration — `HostsFile`

`HostsFile` (`Lib/HostsFile`) parses `/etc/hosts`-format tables and
ships an `asResolverBackend(fallback)` adapter that fits the
`StubResolverBackend` shape directly. Hosts-first behaviour matches
glibc's `nsswitch.conf` `hosts: files dns` line:

```ts
import {
  HostsFile, ResolvConf, StubResolver, UDPClient, PacketTypes,
} from 'dns2ts';

const hosts = HostsFile.fromFile();           // /etc/hosts
const conf = ResolvConf.fromFile();           // /etc/resolv.conf
const dns = UDPClient.request({dns: conf.nameservers[0]});

const stub = new StubResolver({
  resolver: hosts.asResolverBackend(dns),     // hosts → DNS fallback
  search: conf.search,
  ndots: conf.options.ndots,
});

await stub.resolve('printer.local', PacketTypes.A);   // hits /etc/hosts
await stub.resolve('cloudflare.com', PacketTypes.A);  // misses → DNS
```

`HostsFile.lookup(name, type)` returns one of three shapes:

- `{kind: 'match', records}` — name + type both present.
- `{kind: 'nodata'}` — name in file, no record of the requested type.
  The adapter synthesizes a NOERROR response with empty answers and
  *does not* fall through (RFC 1034 §4.3.2 NODATA shape, glibc
  strict-files semantics).
- `{kind: 'miss'}` — name not in file. The adapter calls the
  fallback.

`HostsFile.merge(other)` stacks tables — handy for combining the
system file with a project-local override:

```ts
const merged = HostsFile.fromFile()
  .merge(HostsFile.fromFile('./hosts.local'));
```

**Out of scope for the hosts file:**

- The TTL stamp on synthesized records defaults to `0` (matches
  glibc — `/etc/hosts` is consulted on every call). Override via
  `HostsFile.parse(content, {ttl: 600})` if you want caching to bite.
- `/etc/networks`, `/etc/aliases`, etc. — only the `host(5)` format is
  parsed.
- File-watching / live reload — to pick up changes, build a new
  `HostsFile`.