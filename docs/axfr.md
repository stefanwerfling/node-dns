# AXFR — full zone transfer (RFC 5936)

AXFR is the protocol primary nameservers use to ship the entirety of a
zone to secondary nameservers. It runs over TCP (or TLS) — never UDP. The
exchange is one query (`QTYPE = AXFR`, code 252) followed by a stream of
response messages whose first answer is the zone's SOA and whose final
answer is the same SOA again. Everything between the two SOAs is the
zone's records, in any order.

dns2ts implements both halves: a `Zone` helper that produces AXFR
responses from records you have, and an `AxfrClient` that consumes them.

## Server side — serving AXFR

Build a `Zone` from a master file (or by hand), then dispatch on the
question type in your handler:

```ts
import {DnsServer, Packet, Zone, PacketTypes} from 'dns2ts';

const zone = Zone.fromZoneFile(`
$ORIGIN example.com.
$TTL 3600
@   IN SOA ns1 admin (2024010101 7200 3600 1209600 3600)
@   IN NS  ns1
@   IN MX  10 mail
www IN A   192.0.2.1
`);

const server = new DnsServer({
  tcp: true,
  // tls: { options: { cert, key } },              // optional: AXFR over DoT
  handle: (request, send) => {
    const q = request.questions[0];

    if (q.type === PacketTypes.AXFR) {
      send(zone.toAxfrPackets(request));
      return;
    }

    // … handle normal queries (A, AAAA, MX, …) …
  },
});

await server.listen({tcp: 53});
```

`zone.toAxfrPackets(query)` returns a `Packet[]`. Passing the array to
`send` writes every packet as a length-prefixed frame on the same TCP/TLS
connection before closing it. This is the multi-message
`send(Packet | Packet[])` semantics introduced for AXFR — see the
[server guide](dns-servers.md).

### Single-message vs. multi-message AXFR

`toAxfrPackets` returns **one** message when the SOA-bracketed answer set
fits in a single 64 KiB DNS message (RFC 1035 §4.2.2's TCP length-prefix
ceiling is 65535 bytes). This is the common case for small-to-medium
zones and matches the shape RFC 5936 §2.2 describes for the simplest
valid AXFR exchange.

Larger zones are automatically split across messages: records are pushed
greedily into the current frame, the encoded length is rechecked after
each push, and once the budget is hit the offending record is rolled back
into a fresh frame. The first frame starts with the zone's SOA, the last
frame ends with the same SOA, and every frame carries the original QID,
the original question, and `aa = 1`. Pass the resulting array straight
to `send([…])` — the TCP/TLS server writes every frame as a
length-prefixed message before closing the connection.

```ts
// Default: 65535-byte budget per message.
send(zone.toAxfrPackets(request));

// Custom budget — useful for testing the split path or for transports
// that impose tighter limits.
send(zone.toAxfrPackets(request, {maxMessageSize: 16384}));
```

`Zone.AXFR_MAX_MESSAGE_SIZE` exposes the 65535 ceiling as a constant.
`toAxfrPackets` throws if a single record cannot fit in any message of
the requested size — that signals a malformed zone (e.g. a TXT record
larger than 65535 bytes), not a splittable case.

### Authenticating AXFR

AXFR is **not** authenticated by the protocol itself. Anybody who can reach
your TCP port can request the entire zone unless you protect it. Three
common defenses, often layered:

- **IP allow-list** in your DnsServer handler:

  ```ts
  handle: (request, send, client) => {
    const sock = client as net.Socket;
    if (request.questions[0]?.type === PacketTypes.AXFR &&
        !ALLOWED_SECONDARIES.includes(sock.remoteAddress)) {
      const refused = Packet.createResponseFromRequest(request);
      refused.questions = request.questions.slice();
      refused.header.rcode = 5;   // REFUSED
      send(refused);
      return;
    }
    // …
  }
  ```

- **TSIG** on the AXFR query and response. See the [TSIG guide](tsig.md);
  combine with `Tsig.sign`/`verify` to require a shared key on both sides.

- **DoT (TLS) transport** with mutual TLS via `requestCert: true` in
  `tls.TlsOptions`, optionally pinning client cert subjects.

For production you almost certainly want at least one of these — public
zone leakage via AXFR is a recurring incident pattern.

## Client side — `AxfrClient`

```ts
import {AxfrClient, ClientOptionsProtocol} from 'dns2ts';

const transfer = AxfrClient.request({
  dns: 'ns1.example.com',
  port: 53,                                   // default for tcp
  // protocol: ClientOptionsProtocol.tls,    // for AXFR over DoT
});

const {soa, records} = await transfer('example.com');

console.log(soa.packetType.serial);           // SOA serial
console.log(records.length);                  // every record returned (incl. opening SOA)
```

The returned function opens **one** TCP/TLS connection per call, sends one
AXFR query, and resolves once the closing SOA is observed. The closing SOA
is stripped from `records` (it's a marker, not data); the opening SOA is
included as `records[0]` and also exposed as `soa` for convenience.

### Termination conditions

- **Normal**: second SOA seen → resolves with `{soa, records}`.
- **Premature close**: server closes the connection before a second SOA →
  promise rejects with `Error: AXFR connection closed before final SOA was seen`.
- **Network error**: socket emits `error` → promise rejects with that error.

### TLS to a self-signed server

The bundled client uses Node's default cert store. To talk to a self-signed
DoT endpoint in a lab, build the connection yourself or set
`NODE_TLS_REJECT_UNAUTHORIZED=0` in that process. Production deployments
should use a proper certificate.

## IXFR (RFC 1995)

IXFR — incremental zone transfer — is **not** implemented yet. A primary
that doesn't speak IXFR (or a secondary that doesn't have a recent enough
serial) falls back to AXFR per RFC 1995 §4. Until IXFR lands, every refresh
re-fetches the whole zone, which is fine up to a few thousand records.

## Operational notes

- **Zone refresh cadence** — secondaries poll the SOA every `refresh`
  seconds (the third number in your SOA record). When the SOA serial
  increments, they trigger an IXFR / AXFR. Keep `refresh` reasonable —
  typically 1-4 hours.
- **NOTIFY** (RFC 1996) lets the primary push a hint to secondaries that a
  new serial exists. See the [NOTIFY guide](notify.md) for the
  `NotifyClient` (primary side) and the opcode-dispatch pattern on the
  secondary side.
- **Serial numbers** must increment monotonically (RFC 1982 serial-number
  arithmetic). The common convention is `YYYYMMDDNN`. dns2ts does not
  enforce this — it's your zone editor's job.

## Putting it all together

A small primary serving a single zone, with TSIG-authenticated AXFR
limited to a known secondary IP:

```ts
import {DnsServer, Packet, Zone, PacketTypes, Tsig, TsigKey, TsigAlgorithm} from 'dns2ts';
import net from 'net';

const zone = Zone.fromZoneFile(/* … */);
const tsigKey = new TsigKey('ax-key.', TsigAlgorithm.HMAC_SHA256, Buffer.from('shared'));
const ALLOWED = new Set(['198.51.100.7']);

const server = new DnsServer({
  tcp: true,
  handle: async (request, send, client) => {
    const sock = client as net.Socket;

    if (request.questions[0]?.type !== PacketTypes.AXFR) {
      send(/* normal handling */);
      return;
    }

    if (!ALLOWED.has(sock.remoteAddress!)) {
      const refused = Packet.createResponseFromRequest(request);
      refused.questions = request.questions.slice();
      refused.header.rcode = 5;
      send(refused);
      return;
    }

    // … TSIG verification of the request would go here …
    const packets = zone.toAxfrPackets(request);
    // … TSIG-sign each response packet …
    send(packets);
  },
});

await server.listen({tcp: 53});
```