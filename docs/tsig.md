# TSIG — transaction signatures (RFC 8945)

TSIG attaches an HMAC over the DNS message to the additional section,
authenticating both the sender and the message contents. It is the standard
mechanism for protecting AXFR, dynamic updates, and any sensitive query
between known parties.

dns2ts implements TSIG using Node's built-in `crypto`. No external
dependencies, no native modules.

## Supported algorithms

| Algorithm name        | TsigAlgorithm enum     | HMAC                  |
| --------------------- | ---------------------- | --------------------- |
| `hmac-md5.sig-alg.reg.int.` | `HMAC_MD5`       | HMAC-MD5 (legacy)     |
| `hmac-sha1.`          | `HMAC_SHA1`            | HMAC-SHA1             |
| `hmac-sha224.`        | `HMAC_SHA224`          | HMAC-SHA224           |
| `hmac-sha256.`        | `HMAC_SHA256` (default)| HMAC-SHA256           |
| `hmac-sha384.`        | `HMAC_SHA384`          | HMAC-SHA384           |
| `hmac-sha512.`        | `HMAC_SHA512`          | HMAC-SHA512           |

`HMAC_SHA256` is the recommended default for new deployments. MD5 is kept
for compatibility with legacy nameservers; do not pick it for new keys.

## Keys

A `TsigKey` is a triple of name, algorithm, and shared secret. The name is
the "key name" both peers agree on (typically a domain-style label like
`dynamic-update.example.com.`). The secret is opaque bytes; many tools
distribute it base64-encoded.

```ts
import {TsigKey, TsigAlgorithm} from 'dns2ts';

const key = new TsigKey(
  'dynamic-update.example.com.',
  TsigAlgorithm.HMAC_SHA256,
  Buffer.from('base64secret==', 'base64'),
);

// Or from a raw string (useful when you control both sides)
const lab = new TsigKey('lab.', TsigAlgorithm.HMAC_SHA256, Buffer.from('shared-bytes'));
```

## Signing a query

`Tsig.sign(packet, key, options?)` patches the packet's `ARCOUNT`, computes
the HMAC over the canonical wire form, appends the TSIG RR, and returns the
final bytes plus the MAC value (you'll need the MAC to verify the matching
response).

```ts
import {Packet, PacketQuestion, PacketTypes, PacketClass, Tsig} from 'dns2ts';

const query = new Packet();
query.header.id = 0xCAFE;
query.header.rd = 1;
query.questions.push(new PacketQuestion('example.com', PacketTypes.A, PacketClass.IN));

const {buffer: wire, mac: requestMac} = Tsig.sign(query, key);
// `wire` is what you send. Keep `requestMac` to verify the response.
```

`options.timeSigned` lets you pin the `Time Signed` field for tests.
`options.fudge` overrides the default 300 s window. `options.requestMac`
chains a response onto a previously sent request — see below.

## Verifying a received message

```ts
const parsed = Packet.parse(receivedBytes);

const result = Tsig.verify(parsed, receivedBytes, key, {
  requestMac: requestMac,        // for responses; omit for queries
});

if (!result.valid) {
  // result.reason explains: 'key name mismatch' / 'MAC verification failed' / 'fudge window…'
  throw new Error(`TSIG check failed: ${result.reason}`);
}

// result.tsig is the parsed TSIG RR; useful for logging or echoing the
// original-id / time-signed fields.
console.log(result.tsig?.originalId);
```

The `receivedBytes` second argument matters: TSIG verification needs the
**exact** bytes the sender computed the MAC over. If you re-serialize the
parsed packet (`packet.toBuffer()`), DNS name compression may produce
different bytes and the MAC will mismatch. dns2ts handles this by storing
`PacketResource.byteStart` during decode, so `Tsig.verify` slices the
original buffer.

## Request → response chaining

RFC 8945 §5.3.2.3 requires the response MAC to be computed over
`(request_mac || response_message)`. `Tsig.sign` does this when you pass
`requestMac`:

```ts
// Server side: verify the incoming request, then build and sign the response
const reqCheck = Tsig.verify(parsedRequest, requestBytes, key);
if (!reqCheck.valid) throw new Error(reqCheck.reason);

const reply = Packet.createResponseFromRequest(parsedRequest);
reply.header.qr = 1;
// … push answer records …

const {buffer: replyBytes} = Tsig.sign(reply, key, {
  requestMac: reqCheck.tsig!.mac,
});
```

The client then verifies with the same `requestMac` it remembered:

```ts
const respCheck = Tsig.verify(parsedResponse, responseBytes, key, {
  requestMac: requestMac,
});
```

Without the `requestMac`, response verification fails — that's the
mechanism that prevents an attacker from replaying captured response bodies
under different requests.

## Fudge window

The "fudge" is the maximum clock skew between sender and receiver in
seconds. `Tsig.verify` enforces `|now − timeSigned| ≤ fudge` and returns
`{valid: false, reason: 'fudge window violated'}` outside the window.

Defaults: `fudge = 300` (5 minutes), matching the BIND default. Use
`options.now` to inject a clock for tests, or `options.skipTimeCheck: true`
to replay recorded traffic.

```ts
const result = Tsig.verify(parsed, receivedBytes, key, {
  now: 1_700_000_100,             // inject "current time"
});
```

For production servers, the takeaway is to keep clock skew under a few
minutes (NTP) — otherwise legitimate clients hit the fudge window and
silently fail.

## Replay protection

TSIG itself does not implement nonce-based replay protection beyond the
fudge window. If an attacker captures a valid signed query and replays it
within the window, the MAC still verifies. Mitigations:

- Keep the fudge small (300 s is fine for most deployments; 60 s is fine
  for dynamic updates).
- Track `(timeSigned, originalId)` pairs and reject duplicates inside the
  current window.
- Pair TSIG with a transport that provides ordering (TCP/TLS) when
  authenticating zone transfers.

## Error reasons returned by `verify`

| `result.reason`              | Cause                                               |
| ---------------------------- | --------------------------------------------------- |
| `no TSIG record`             | The packet has no TSIG RR in its additional section |
| `key name mismatch`          | TSIG RR uses a different key name than yours        |
| `algorithm mismatch`         | Same name, different algorithm                      |
| `MAC verification failed`    | Wrong secret, tampered message, or wrong requestMac |
| `fudge window violated: …`   | `|now − timeSigned|` outside the fudge              |

A `valid: false` result always carries a reason; log it but never expose it
to untrusted callers in detail (it leaks information about your validation
state).

## End-to-end on the server side

Server handlers receive the raw post-`preRequest` wire bytes as the 4th arg
of the `request` event (and `ServerRequestHandler`). Pass them to
`Tsig.verify` directly — never re-encode the parsed packet for verification.
The `send` callback also accepts `Buffer`, so a `Tsig.sign(reply, ...).buffer`
goes back over the wire byte-for-byte.

```ts
import {DnsServer, Tsig, TsigError, Update, UpdateRcode, PacketOpcode} from 'dns2ts';

const server = new DnsServer({
  udp: true,
  handle: (request, send, _client, raw) => {
    if (request.header.opcode !== PacketOpcode.UPDATE) {
      // … normal query path …
      return;
    }

    const verified = Tsig.verify(request, raw, key);

    if (!verified.valid) {
      const reply = Update.buildResponse(request, UpdateRcode.NOTAUTH);
      send(Tsig.sign(reply, key, {error: TsigError.BADSIG}).buffer);
      return;
    }

    const rcode = Update.applyToZone(zone, Update.parse(request));
    const reply = Update.buildResponse(request, rcode);
    send(Tsig.sign(reply, key, {requestMac: verified.tsig!.mac}).buffer);
  },
});
```

On the client side, `UpdateClient.request(...)` accepts a raw `Buffer`
(`Tsig.sign(...).buffer`) so the bytes that were signed are exactly the
bytes that go on the wire.

## When to use TSIG

- Securing AXFR (zone transfer) — the canonical use; always pair TSIG with
  IP allow-listing for layered defense.
- Authenticating dynamic updates (RFC 2136) — see the end-to-end snippet
  above for the full handler shape.
- Internal recursor → authoritative server hops where you control both
  ends and want fast HMAC auth without TLS overhead.

For untrusted client → server flows, prefer DoT or DoH (TLS-based mutual
authentication is more flexible than a shared secret).