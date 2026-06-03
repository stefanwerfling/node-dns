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

Add a `cookies` block to the UDP transport options:

```ts
import {Buffer} from 'node:buffer';
import {randomBytes} from 'node:crypto';
import {DnsServer, UDPServer} from 'dns2ts';

const server = new DnsServer({
  udp: {
    cookies: {
      // KEEP THIS STABLE across restarts. Rotating it forces every
      // active client to seed a fresh server cookie (one extra
      // round-trip). 16+ bytes recommended.
      secret: randomBytes(32),
    },
  },
  handle: (req, send) => {
    // Only valid-cookie + lenient-mode-no-cookie queries reach here.
    send(Packet.createResponseFromRequest(req));
  },
});

await server.listen();
```

The same option is accepted by the standalone `UDPServer`:

```ts
const udp = new UDPServer({udp: {cookies: {secret: SECRET}}});
```

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

## What's not implemented yet

- Server-side cookies are UDP-only right now. TCP/TLS sessions are
  inherently spoof-resistant (you can't forge the three-way
  handshake), so cookies there are mostly redundant. If you need
  them for policy reasons (e.g. ensure cookie-aware client across
  transports), wire `EdnsCookie.verifyServerCookie` into your TCP
  handler manually.
- Cookie-aware client-side automation. `EdnsCookie.generateClientCookie`
  and `verifyServerCookie` work, but UDPClient doesn't yet
  remember server cookies across queries.