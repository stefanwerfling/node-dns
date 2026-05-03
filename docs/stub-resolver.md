# Stub resolver

`StubResolver` adds resolver(5) / glibc-style **search-path expansion**
to any existing transport. It does no networking on its own — you
hand it a backend resolver function and it sequences calls per the
classic short-name / `ndots` rules.

This is the layer between "raw DNS query" and "host name in a config
file". A user typing `ssh server` expects `server.corp.local` to be
tried via the configured search domains; `StubResolver` is the piece
that makes that happen.

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

## Out of scope

- **Nameserver rotation / failover** — the stub doesn't iterate over
  `parsed.nameservers`. Wire that into your backend if you need it
  (the existing `DNS` class already does parallel-try across servers).
- **Caching** — every `resolve()` call invokes the backend for each
  candidate. Use `DnsCache` (or any cache the backend already
  provides) when latency matters.
- **`/etc/hosts` lookup** — host-file resolution is glibc's job, not
  the DNS layer. A separate helper could be added if there's
  demand.