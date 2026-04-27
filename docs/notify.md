# NOTIFY (RFC 1996)

NOTIFY is the small companion protocol that lets a primary nameserver
push-notify its secondaries that a zone has changed. Without NOTIFY a
secondary only learns about new zone data when its periodic `refresh`
interval (the third number in the SOA) expires; with NOTIFY, propagation
is sub-second.

The wire format is a normal DNS message with `opcode = NOTIFY (4)` and the
`AA` flag set, asking for the zone's SOA record. The secondary replies
with the same opcode echoed back; whether or not the reply contains
useful data, its arrival is the secondary's "got it, I'll go check"
signal.

dns2ts ships a `NotifyClient` for the primary side. Acting on a NOTIFY
on the secondary side is a few lines of code in your existing handler —
the protocol doesn't need a dedicated server class.

## Primary side — sending NOTIFY

```ts
import {NotifyClient, ClientOptionsProtocol} from 'dns2ts';

const notify = NotifyClient.request({
  dns: '198.51.100.7',                          // secondary nameserver
  port: 53,                                      // default
  // protocol: ClientOptionsProtocol.tcp,        // optional; UDP by default
});

const response = await notify('example.com');
console.log(response.header.rcode);              // 0 = NOERROR ack
```

You typically call `notify()` once per secondary every time you change
the zone. RFC 1996 §3.6 recommends sending the NOTIFY several times with
backoff if the secondary doesn't ack — production setups loop with
exponential backoff over a few minutes before giving up.

### Including the new SOA

RFC 1996 §3.7 lets you stick the new SOA into the answer section as a
hint. The secondary can compare the serial against its own without
issuing a follow-up SOA query.

```ts
import {NotifyClient, SOA} from 'dns2ts';

const notify = NotifyClient.request({
  dns: '198.51.100.7',
  sourceSoa: new SOA(
    'ns1.example.com',
    'admin.example.com',
    2024010102,                                  // new serial
    7200, 3600, 1209600, 3600,
  ),
});

await notify('example.com');
```

This is optional and not all secondaries use it; sending it is harmless.

### Transport

UDP is the default and is fine for the typical "small message, fast
response" NOTIFY exchange. Switch to TCP/TLS when:

- You're sending a large source SOA (rare; SOAs are small).
- The secondary requires DoT for all traffic.
- Your network drops UDP between the two hosts.

```ts
NotifyClient.request({
  dns: 'secondary.example.com',
  protocol: ClientOptionsProtocol.tls,           // DoT, port 853 by default
});
```

## Secondary side — handling NOTIFY

The DnsServer's `request` event already gives you the parsed packet —
just dispatch on `request.header.opcode`:

```ts
import {DnsServer, Packet, PacketOpcode} from 'dns2ts';

const server = new DnsServer({
  udp: true,
  tcp: true,
  handle: async (request, send) => {
    if (request.header.opcode === PacketOpcode.NOTIFY) {
      await handleNotify(request, send);
      return;
    }

    // … normal QUERY handling …
  },
});

async function handleNotify(request: Packet, send: (r: Packet) => void): Promise<void> {
  const zoneName = request.questions[0]?.name;
  const allowed = ALLOWED_PRIMARIES.includes(/* client IP */);

  if (!allowed || !zoneIsAuthoritative(zoneName)) {
    const refused = Packet.createResponseFromRequest(request);
    refused.questions = request.questions.slice();
    refused.header.opcode = PacketOpcode.NOTIFY;
    refused.header.rcode = 9;                    // NOTAUTH
    send(refused);
    return;
  }

  // Ack the NOTIFY immediately; do the real work in the background.
  const ack = Packet.createResponseFromRequest(request);
  ack.questions = request.questions.slice();
  ack.header.opcode = PacketOpcode.NOTIFY;
  ack.header.aa = 1;
  ack.header.rcode = 0;                          // NOERROR
  send(ack);

  // Then: query the primary's SOA, compare serials, run AXFR/IXFR if newer.
  scheduleZoneRefresh(zoneName);
}
```

The acknowledgement should happen **before** you trigger the actual zone
fetch — RFC 1996 §3.10 expects a quick ack so the primary stops
retransmitting. Real refresh work (SOA query, AXFR, persisting the new
zone) runs out of band.

### Validating the source

NOTIFY is unauthenticated by default. Anybody who can reach your
nameserver port can claim "your zone changed". Two protections you
should layer:

- **IP allow-list** of known primaries.
- **TSIG** on the NOTIFY exchange (RFC 1996 §3.11) — most production
  primary↔secondary pairs share a TSIG key already used for AXFR.

## When to use NOTIFY

- You run a primary with secondaries that need fast propagation.
- You're integrating with an existing DNS infrastructure that expects
  NOTIFY (most do — BIND, Knot, NSD all send/receive NOTIFY by default).

If you only have a single authoritative server, NOTIFY does nothing
useful — it's the "tell other servers" protocol, not "log my own
changes". Use a normal config-reload mechanism instead.

## Related

- [Zone files](zone-files.md) — how to load the zone you're notifying about.
- [AXFR](axfr.md) — the protocol the secondary uses to actually fetch
  the new data after a NOTIFY.
- [TSIG](tsig.md) — authenticate the NOTIFY exchange end-to-end.