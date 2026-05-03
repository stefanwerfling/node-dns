# mDNS (Multicast DNS)

`MdnsClient` is a minimal RFC 6762 client. mDNS is the protocol behind
`.local` host names and Bonjour / Avahi service discovery — wire
format identical to unicast DNS, but the framing and semantics differ.

## What's different from unicast DNS

- **Multicast group, not a single server.** Queries go to
  `224.0.0.251:5353` (IPv4) or `[ff02::fb]:5353` (IPv6); every device
  on the segment listens.
- **Many-to-many.** A single query can collect responses from
  multiple devices — there is no "first response wins" pattern.
  `MdnsClient.request` returns an *array* of `MdnsResponse`, one per
  responding device.
- **No transaction ID.** RFC 6762 §18.1 fixes the ID at 0 for
  unsolicited multicast queries; the client follows that.
- **QU bit** (RFC 6762 §5.4) — the top bit of the QCLASS field on a
  question asks the responder to reply via *unicast* to the source
  port instead of multicast. Useful for one-shot lookups where you
  don't want every other device to see the answer.
- **Cache-flush bit** (RFC 6762 §10.2) — the top bit of the CLASS
  field on an answer RR signals "this RRset replaces any previously
  cached records for the same name/type". Constant exposed as
  `MDNS_CACHE_FLUSH_BIT = 0x8000`.

## Quick start

```ts
import {MdnsClient, PacketTypes} from 'dns2ts';

const resolve = MdnsClient.request({
  // defaults: 224.0.0.251:5353 / udp4 / 1000ms timeout
});

const responses = await resolve('printer.local', PacketTypes.A);
for (const r of responses) {
  console.log(`${r.sender.address}:${r.sender.port}`,
              r.answers.map(rr => rr.packetType));
}
```

## Configuration

```ts
MdnsClient.request({
  multicastAddr: '224.0.0.251',  // default IPv4 mcast group
  port: 5353,                    // default mDNS port
  family: 'udp4',                // 'udp4' | 'udp6'
  timeoutMs: 1000,               // collect responses for this long
  unicastResponse: false,        // set the QU bit on the question
  interfaceAddress: undefined,   // bind to a specific local interface
  joinMulticastGroup: true,      // call socket.addMembership()
});
```

`joinMulticastGroup` defaults to `true` when `multicastAddr` looks
like a multicast address (224.0.0.0/4 or ff00::/8) and `false`
otherwise. The flag exists so tests can drive the client over a
unicast loopback responder without the host actually joining a
multicast group.

## QU (Query Unicast) bit

Setting `unicastResponse: true` flips the top bit of QCLASS on the
outgoing question (RFC 6762 §5.4). The responder honours it by
sending a unicast reply to your source port, leaving the rest of the
segment quiet:

```ts
const resolve = MdnsClient.request({
  unicastResponse: true,
  timeoutMs: 500,    // unicast tends to be faster than waiting for the full mcast budget
});

const [r] = await resolve('printer.local', PacketTypes.A);
```

Note that some responders ignore the QU bit and still multicast.

## Service discovery (DNS-SD, RFC 6763)

`ServiceDiscovery` is the helper that composes the four DNS-SD
queries on top of `MdnsClient`:

1. `PTR _<service>._<protocol>.<domain>` → list of instance names
2. `SRV <instance>` → host + port
3. `TXT <instance>` → key/value metadata
4. `A`/`AAAA` of the SRV target → IP addresses

```ts
import {ServiceDiscovery} from 'dns2ts';

const instances = await ServiceDiscovery.browse({
  serviceType: '_http._tcp',
  // domain: 'local',         // default
  // timeoutMs: 1000,          // default
  // resolveMissing: true,     // issue follow-ups when additionals lack records
});

for (const inst of instances) {
  console.log(inst.name, inst.host, inst.port, inst.txt, inst.addresses);
}
```

RFC 6763 §12 encourages responders to bundle SRV + TXT + A/AAAA into
the *additionals* section of the PTR response. `ServiceDiscovery`
takes that fast path — when records are present a single roundtrip
is enough — and only issues follow-up queries for the gaps.

If you already know the instance name, skip the PTR walk:

```ts
const inst = await ServiceDiscovery.resolveInstance(
  'tv._airplay._tcp.local',
  {mdns: {timeoutMs: 500}}
);
```

TXT entries are decoded per RFC 6763 §6.3:

- `"flag"` (no `=`) → `flag: true`
- `"key=value"` → `key: 'value'`
- `"key="` → `key: ''`
- Empty entries and missing keys are skipped.
- First occurrence of a duplicated key wins (§6.4).

## Tests

The test suite drives the client over `127.0.0.1` instead of a real
multicast group. The `joinMulticastGroup` flag default makes that
"just work": the client detects the unicast address, skips the group
join, and behaves like a regular UDP client over loopback. See
`Test/mdns.ts` for the pattern.

## Server side — `MdnsServer`

Listens on the multicast group + 5353 and emits `request` events
shaped like every other server in the project. The handler decides
what to respond with — there is no built-in record store.

```ts
import {MdnsServer, Packet, PacketResource, PacketClass, A} from 'dns2ts';

const server = new MdnsServer({
  // multicastAddr: '224.0.0.251',  // default IPv4 mcast group
  // port: 5353,                     // default mDNS port
  // family: 'udp4',                 // 'udp4' | 'udp6'
  // joinMulticastGroup: true,       // auto-detected from multicastAddr
  // reuseAddr: true,                // share 5353 with avahi-daemon etc.
});

server.on('request', (msg, send, rinfo) => {
  // Match the question(s) and respond.
  if (msg.questions[0]?.name === 'printer.local') {
    const reply = new Packet();
    reply.header.qr = 1;
    reply.header.aa = 1;
    reply.questions = msg.questions.slice();
    reply.answers = [
      new PacketResource('printer.local', new A('192.168.1.5'),
                         PacketClass.IN, 120)
    ];
    send(reply);   // 'auto' — multicast unless any question carried QU
  }
});

await server.listen();
```

`send(msg, target?)` decides the routing:

- `'auto'` (default) — multicast, *unless* any question on the
  request had the QU bit set, in which case unicast back to the
  source.
- `'multicast'` — always send to the configured multicast group.
- `'unicast'` — always send back to `rinfo.address:rinfo.port`.

`qr=1` traffic (other devices' responses) and malformed datagrams are
silently filtered before reaching the handler — the multicast group
sees a lot of unrelated chatter.

### Probing — `MdnsProbe`

Before a host can claim a name on the link it must verify that no
other responder is using it. RFC 6762 §8 describes the probe / announce
dance: send three queries 250 ms apart for the tentative name with the
proposed records in the AUTHORITY section, watch for conflicting
answers, run a lexicographic tiebreak when another host probes the
same name simultaneously (§8.2), and on success multicast at least
two announcements 1 s apart with the cache-flush bit set.

`MdnsProbe.claim()` runs that dance:

```ts
import {
  MdnsProbe, PacketResource, PacketClass, A,
} from 'dns2ts';

const records = [
  new PacketResource('host.local', new A('192.168.1.42'),
                     PacketClass.IN, 120)
];

const result = await MdnsProbe.claim({
  records: records,
  // multicastAddr: '224.0.0.251',  // default
  // port: 5353,                    // default
  // probeAttempts: 3,              // RFC 6762 §8.1 — 3 probes 250ms apart
  // probeIntervalMs: 250,
  // initialJitterMs: 250,          // §8.1 — 0..250ms before first probe
  // announceAttempts: 2,           // §8.3 — 2 announcements
  // announceIntervalMs: 1000,
});

if (result.result === 'claimed') {
  // Start serving the name with MdnsServer.
} else {
  // result.conflictRecord — what someone else asserted; rename + retry.
}
```

All tentative records must share one owner name — the helper probes a
single name at a time. Multiple types (`A` + `AAAA` + `TXT` + …) for
the same name go into one `claim()` call.

The probe phase listens for two conflict shapes:

- **Response (qr=1)** carrying records for our name with rdata not in
  our tentative set → conflict. Caller renames.
- **Query (qr=0)** for our name carrying authority records — another
  host is also probing. Run §8.2 lexicographic tiebreak: the host
  whose record set sorts *later* (canonical type / class / RDATA byte
  comparison, name excluded per §8.2.1, cache-flush bit stripped)
  wins. The losing side returns `'conflict'`.

`MdnsProbe.canonicalRecordKey(record)` and
`MdnsProbe.compareRecordSets(a, b)` are exposed for callers that want
to reason about tiebreak outcomes outside of an actual probe.

`bindPort` lets tests bind to a port other than the destination
`port` so a peer dgram socket can occupy `port` directly. In
production both default to 5353 (RFC 6762 §15 expects source port
5353 too).

### Announce + goodbye — `MdnsServer.announce` / `goodbye`

After a successful probe (and during normal lifetime, periodically),
the responder multicasts unsolicited responses so peer caches stay
fresh. RFC 6762 §10.1 also asks the responder to send a "goodbye"
just before shutdown — same shape but with TTL=0 — so peers flush
the entries immediately instead of waiting for natural expiry.

The server exposes both as one-shot primitives. Scheduling is up to
application code:

```ts
import {MdnsServer, PacketResource, PacketClass, A} from 'dns2ts';

const server = new MdnsServer();
await server.listen();

const records = [
  new PacketResource('host.local', new A('192.168.1.42'),
                     PacketClass.IN, 120),
];

// Initial announce (post-probe, post-listen).
await server.announce(records);

// Periodic re-announce — RFC 6762 §10 mentions a back-off schedule
// (1s, 2s, 4s, 8s, …) so reassessing fresh nodes happens cheaply.
const intervals = [1000, 2000, 4000, 8000, 16000];
let i = 0;
const tick = (): void => {
  if (i >= intervals.length) {
    return;
  }
  setTimeout(async () => {
    await server.announce(records);
    i++;
    tick();
  }, intervals[i]);
};
tick();

// Shutdown — broadcast TTL=0 announcements so peers flush their
// caches, then close the socket. RFC 6762 §10.1 recommends sending
// the goodbye twice with a brief delay; the caller controls that.
await server.goodbye(records);
await new Promise(r => setTimeout(r, 250));
await server.goodbye(records);
server.close();
```

Both methods take an explicit record list (the server keeps no
record store) and apply:

- the cache-flush bit (RFC 6762 §10.2 — top bit of CLASS) on every
  record, signalling "this RRset replaces any previously cached
  records for the same name+type",
- TTL=0 on goodbye, TTL preserved on announce.

The records you pass in are never mutated — copies are made before
the wire packet is built.

### Out of scope (for now)

- **Continuous-announcement schedule** — provided as primitives, not
  as a built-in scheduler. Wire up `setTimeout` / a small helper
  yourself if you need automatic decreasing-interval re-announces.
- **Re-probing** on conflict — `MdnsProbe.claim()` returns
  `'conflict'` and the caller decides how to rename + retry; the
  helper doesn't loop on its own.