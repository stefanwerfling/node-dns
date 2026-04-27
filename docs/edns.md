# EDNS(0) options

EDNS(0) (RFC 6891) is the extension mechanism that lets DNS messages carry
metadata beyond the original 12-byte header. dns2ts implements six EDNS
options today; adding more is mechanical.

## The OPT record

EDNS data lives in a special `OPT` resource record (type 41) in the
**additional** section. Every option attaches to the same OPT record. Build
the record with `EDNS.createResource`:

```ts
import {EDNS, EdnsECS, EdnsCookie, EdnsPadding, Packet} from 'dns2ts';

const opt = EDNS.createResource([
  new EdnsECS('192.0.2.0/24'),
  new EdnsCookie(EdnsCookie.generateClientCookie()),
  new EdnsPadding(128),
]);

const query = new Packet();
// … set up question(s) …
query.additionals.push(opt);
```

Decoding works the same way: `packet.additionals.find(r => r.packetType instanceof EDNS)?.packetType.rdata`
yields the array of `EdnsOption` instances.

## Option summary

| Option              | Code | Class                 | RFC                  |
| ------------------- | ---: | --------------------- | -------------------- |
| Name Server ID      | 3    | `EdnsNsid`            | RFC 5001             |
| Client Subnet       | 8    | `EdnsECS`             | RFC 7871             |
| Cookies             | 10   | `EdnsCookie`          | RFC 7873 / RFC 9018  |
| TCP Keepalive       | 11   | `EdnsKeepalive`       | RFC 7828             |
| Padding             | 12   | `EdnsPadding`         | RFC 7830             |
| Extended DNS Errors | 15   | `EdnsExtendedError`   | RFC 8914             |

Unknown option codes survive a parse → re-encode roundtrip via the catch-all
"unknown option" debug path; they just don't produce a typed object.

## EdnsECS — Client Subnet (RFC 7871)

A recursor forwards a hint about the original client's network so an
authoritative server can return a network-tailored answer.

```ts
new EdnsECS('203.0.113.0/24');     // typical: just IP/prefix
new EdnsECS('2001:db8::/32');      // IPv6 also works (not yet emitted on encode)
```

After decoding, the option exposes `family`, `sourcePrefixLength`,
`scopePrefixLength`, and `ip`.

## EdnsCookie — DNS Cookies (RFC 7873 + RFC 9018)

Cookies provide cheap server authentication of clients (anti-spoofing for
amplification attacks) without the cost of TCP. The wire format is two
opaque blobs: a fixed-size 8-byte client cookie and an 8-32 byte server
cookie.

### Client side

```ts
import {EdnsCookie, EDNS} from 'dns2ts';

// First query: send only a client cookie (the server has nothing to echo yet)
const clientCookie = EdnsCookie.generateClientCookie();   // 8 random bytes
const opt1 = EDNS.createResource([new EdnsCookie(clientCookie)]);

// Server replies with its server cookie. Cache it per server, then…
const stored = response.additionals
  .find(r => r.packetType instanceof EDNS)
  ?.packetType.rdata.find(o => o instanceof EdnsCookie) as EdnsCookie | undefined;

if (stored?.serverCookie) {
  // Subsequent queries: include both cookies
  const opt2 = EDNS.createResource([
    new EdnsCookie(clientCookie, stored.serverCookie),
  ]);
}
```

Per RFC 7873 §5.2, clients should reuse the same client cookie per
destination server until the server signals a refresh.

### Server side (RFC 9018 algorithm)

`EdnsCookie` ships an RFC 9018-style server-cookie construction using
HMAC-SHA256 truncated to 128 bits. The output is **24 bytes**:

```
1 byte  version (= 1)
3 bytes reserved (zero)
4 bytes unix timestamp
16 bytes truncated HMAC-SHA256(secret, client_cookie ‖ header ‖ client_ip)
```

Generate and verify:

```ts
import {EdnsCookie} from 'dns2ts';

// Long-lived server secret. Rotate with overlap if you care about
// continuity across restarts.
const secret = readFileSync('cookie-secret.bin');     // ≥ 16 bytes recommended

// On each query that includes a client cookie:
const clientIp = Buffer.from([198, 51, 100, 7]);      // 4 bytes IPv4 / 16 bytes IPv6
const fresh = EdnsCookie.computeServerCookie(
  parsedClientCookie,
  clientIp,
  secret,
);
// Echo `fresh` back as `serverCookie`.

// When a client sends back a previously issued server cookie, verify:
const ok = EdnsCookie.verifyServerCookie(
  receivedServerCookie,
  receivedClientCookie,
  clientIp,
  secret,
  {maxAgeSeconds: 3600},   // optional age window
);
```

`verifyServerCookie` uses `crypto.timingSafeEqual` and checks the embedded
timestamp. Cookies older than `maxAgeSeconds` are rejected even when the
MAC is valid — RFC 9018 §4.2 recommends ~1 hour to 1 day.

## EdnsPadding — RFC 7830

Pads a message to a target length so an observer cannot infer query content
from datagram size — important on DoT/DoH.

```ts
import {EdnsPadding} from 'dns2ts';

new EdnsPadding(128);   // payload is 128 zero bytes
```

A common pattern is "pad to next 128-byte block": compute the encoded size
without padding, then add an `EdnsPadding(target − current)` to round up.

## EdnsNsid — RFC 5001

Used by clients to discover *which physical instance* responded behind an
anycast address — handy for debugging and for operators publishing per-POP
identifiers.

```ts
// Client query: empty payload signals "tell me your NSID"
new EdnsNsid();

// Server response: opaque bytes (commonly UTF-8)
new EdnsNsid('iad-pop-3.dns.example.net');
```

After decoding, `option.data` is a `Buffer`.

## EdnsKeepalive — RFC 7828

Lets a client signal it supports the keepalive option, and lets the server
advertise an idle timeout for the TCP/TLS connection.

```ts
// Client signal: empty payload
new EdnsKeepalive(null);

// Server reply: 16-bit timeout in 100 ms units (so 100 = 10 s)
new EdnsKeepalive(100);
```

A value of `null` after decoding means "no timeout was sent".

## EdnsExtendedError — RFC 8914

Carries a 16-bit info code and optional UTF-8 text explaining *why* a
response is what it is — particularly useful with `SERVFAIL` (DNSSEC bogus,
upstream timeout, blocked by RPZ, etc.).

```ts
import {EdnsExtendedError, ExtendedDnsErrorCode} from 'dns2ts';

new EdnsExtendedError(ExtendedDnsErrorCode.DNSSEC_BOGUS);
new EdnsExtendedError(ExtendedDnsErrorCode.BLOCKED, 'blocked by policy: rpz');
```

The `ExtendedDnsErrorCode` enum lists the 25 codes from the IANA registry
(Other, UNSUPPORTED_DNSKEY_ALGORITHM, …, INVALID_DATA).

## Mixing options

EDNS encodes options in the order you provide them and the decoder
preserves that order:

```ts
const opt = EDNS.createResource([
  new EdnsECS('203.0.113.0/24'),
  new EdnsCookie(clientCookie),
  new EdnsKeepalive(null),
  new EdnsNsid(),
  new EdnsExtendedError(ExtendedDnsErrorCode.STALE_ANSWER, 'cache hit'),
  new EdnsPadding(64),
]);
```

There is no internal ordering requirement at the protocol level (RFC 6891
§6.1.4 leaves the order to the sender), so this works for any combination.

## OPT record metadata

`EDNS.createResource` builds an OPT record with the standard defaults:
class field repurposed as UDP payload size = 512 bytes, TTL field = 0
(extended RCODE / version / Z flags). If you need to advertise a larger
client buffer, build the resource manually:

```ts
import {EDNS, PacketResource, EdnsECS} from 'dns2ts';

const resource = new PacketResource(
  '',                                    // OPT records carry an empty owner name
  new EDNS([new EdnsECS('203.0.113.0/24')]),
  4096,                                  // class field = UDP payload size
  0,                                     // ttl encodes the extended flags
);
```

A 4096-byte buffer size is the typical announcement for resolvers willing to
receive larger responses.