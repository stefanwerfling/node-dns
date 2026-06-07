# DNS Cookies on the server (RFC 7873 + RFC 9018)

DNS Cookies are a lightweight anti-spoofing layer for UDP: every
query carries an 8-byte client cookie, the server returns an
HMAC-keyed server cookie that the client must echo back on
subsequent queries from the same `(client cookie, client IP)`
tuple. An off-path attacker can't observe the server cookie and
therefore can't form a valid query — reflection / amplification
floods that omit or forge cookies get a tiny BADCOOKIE response
instead of a full answer.

Cookies don't help against on-path attackers; pair them with TSIG
(RFC 8945) when you need authenticated channels, and with RRL
(RFC 5358) for resistance to bursts from any single source.

## Enabling

The `cookies` block is accepted on every connection-oriented
transport block (`udp`, `tcp`, `tls`) and is internally backed by
a shared `CookieGuard` validator. Configure it once per transport
you want covered; UDP is the case that benefits most. Example
covers both legs of a hybrid deployment:

```ts
import {Buffer} from 'node:buffer';
import {randomBytes} from 'node:crypto';
import {DnsServer} from 'dns2ts';

// KEEP THIS STABLE across restarts. Rotating it forces every active
// client to seed a fresh server cookie (one extra round-trip).
// 16+ bytes recommended.
const SECRET = randomBytes(32);

const server = new DnsServer({
  udp: {cookies: {secret: SECRET}},
  tcp: {cookies: {secret: SECRET}},
  tls: {options: tlsOpts, cookies: {secret: SECRET}},
  handle: (req, send) => {
    // Only valid-cookie + lenient-mode-no-cookie queries reach here.
    send(Packet.createResponseFromRequest(req));
  },
});

await server.listen();
```

Standalone transports take the same shape:

```ts
new UDPServer({udp: {cookies: {secret: SECRET}}});
new TCPServer({tcp: {cookies: {secret: SECRET}}});
new TLSServer({tls: {options: tlsOpts, cookies: {secret: SECRET}}});
```

## Why cookies on TCP/TLS?

The TCP three-way handshake (and the TLS one on top of it) already
prevents off-path source-IP spoofing, so cookies don't add
anti-spoofing on these transports. They are still useful for two
things:

- **Cross-transport identity** — a client that falls back from UDP
  to TCP (after a TC=1, an RRL slip, or a BADCOOKIE) keeps the same
  cookie pair when both transports share a `ClientCookieJar`
  instance. The server sees the same identity on either leg.
- **Policy uniformity** — `mode: 'strict'` applied to UDP only
  leaves a side door open on TCP. Configuring cookies on all
  enabled transports closes it.

## Acceptance modes

`mode: 'lenient'` (default) — queries without a cookie option pass
through to the handler verbatim. Clients that don't speak cookies
(legacy `dig`, embedded stacks) still get served. Queries WITH a
cookie option are always validated.

`mode: 'strict'` — queries without a cookie get `REFUSED`. Useful
when you can ensure every legitimate client supports cookies.

```ts
new UDPServer({
  udp: {cookies: {secret: SECRET, mode: 'strict'}},
});
```

## Cookie expiry

Server cookies embed a timestamp; `maxAgeSeconds` (default 3600)
caps how old an accepted cookie can be. RFC 9018 §4.2 recommends
1 hour to 1 day depending on threat model. Pass `0` to accept any
MAC-valid cookie regardless of age:

```ts
new UDPServer({
  udp: {cookies: {secret: SECRET, maxAgeSeconds: 86400}}, // 24h
});
```

## Observability

Listen for the `cookieRejected` event to instrument:

```ts
server.on('cookieRejected', (msg, rinfo, reason) => {
  console.log(`drop ${rinfo.address}/${msg.questions[0].name}: ${reason}`);
});
```

`reason` is one of:
- `'no-server-cookie'` — client sent only the client half (first
  query from this client); we issued a server cookie and the
  client will retry.
- `'invalid-cookie'` — MAC mismatch, wrong IP, or expired.
- `'no-cookie-strict'` — strict mode + no cookie option at all.

These rejections do NOT invoke the request handler.

## What the response looks like

For valid-cookie queries: the response carries an OPT RR with a
refreshed cookie option. If your handler already attaches an OPT
(for ECS, NSID, padding, ...), the cookie is added alongside —
the existing OPT is preserved.

For BADCOOKIE: header rcode = 7 (low nibble of 23), OPT TTL's
EXTENDED-RCODE byte = 1 (upper byte of 23 = `0x01 << 24` in the
TTL field per RFC 6891 §6.1.3). The OPT carries the same client
cookie and a freshly-issued server cookie. RFC 7873 §5.4-compliant
clients automatically retry with the new cookie.

For strict-mode REFUSED: header rcode = 5; no cookie issued (no
client cookie to bind one to).

## Client side — `ClientCookieJar`

Both `UDPClient` and `TCPClient` (covering plain TCP and DoT) can
hold the other end of the conversation: attach a client cookie to
every outgoing query, learn the server cookie out of each response,
and retry once on BADCOOKIE with the freshly issued cookie. Enable
it with `cookies` on `ClientOptions`:

```ts
import {UDPClient, TCPClient, ClientCookieJar, ClientOptionsProtocol, PacketTypes, PacketClass} from 'dns2ts';

// `true` allocates a private jar for this client.
const resolve = UDPClient.request({
  dns: '198.51.100.10',
  cookies: true,
});

await resolve('example.com', PacketTypes.A, PacketClass.IN);
// First call: server replies BADCOOKIE, client retries with the
// learned server cookie. Subsequent calls go straight through.
```

Pass a `ClientCookieJar` instance to share cookies across multiple
factories (e.g. when one process talks to several upstreams, or
falls back across transports against the same upstream):

```ts
const jar = new ClientCookieJar();

const overUdp = UDPClient.request({dns: '198.51.100.10', cookies: jar});
const overTcp = TCPClient.request({dns: '198.51.100.10', cookies: jar});
const overTls = TCPClient.request({
  dns: '198.51.100.10',
  port: 853,
  protocol: ClientOptionsProtocol.tls,
  cookies: jar,
});
```

The jar is keyed on `${host}:${port}`, so UDP and TCP both pointing
at `198.51.100.10:53` share one entry — a single client cookie pair
is reused across both transports (RFC 7873 §5.1 cross-transport
identity).

Useful methods:

- `jar.peek(host, port)` — read entry without allocating.
- `jar.forget(host, port)` — drop one upstream (e.g. after secret
  rotation on the server side).
- `jar.clear()` — wipe everything.
- `ClientCookieJar.isBadCookie(response)` — predicate that combines
  the header rcode and OPT TTL upper byte (RFC 6891 §6.1.3) into
  the 12-bit extended rcode 23 check.

The TCP client's BADCOOKIE retry opens a fresh connection (or reuses
the existing pool connection via `option.pool`). The cost on the
non-pooled path is one extra handshake; on the pooled path the retry
rides the same persistent connection that's already open.

## What's not implemented yet

- DoH (`DohClient`) and `GoogleClient` don't speak cookies. DoH
  fronts (HTTPS edge → resolver) typically terminate the resolver
  identity at the edge anyway; adding cookies there is mostly busy
  work.
- AXFR / IXFR / NOTIFY / UPDATE clients don't attach cookies. They
  serve operational paths against trusted upstreams; cookies add no
  value over TSIG which is the existing recommendation.