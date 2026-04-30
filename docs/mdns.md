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

`MdnsClient` is the wire-level primitive — it doesn't compose a
service-discovery walk for you. The DNS-SD pattern stacks four
queries on top:

1. `PTR _http._tcp.local` → list of service instance names.
2. `SRV instance._http._tcp.local` → host + port of each.
3. `TXT instance._http._tcp.local` → key/value metadata.
4. `A`/`AAAA` of the SRV target → IP addresses.

You can compose those with `MdnsClient.request` and collect the
results across responses. A purpose-built DNS-SD helper is on the
roadmap.

## Tests

The test suite drives the client over `127.0.0.1` instead of a real
multicast group. The `joinMulticastGroup` flag default makes that
"just work": the client detects the unicast address, skips the group
join, and behaves like a regular UDP client over loopback. See
`Test/mdns.ts` for the pattern.

## Out of scope (for now)

- **Probing / conflict resolution** (RFC 6762 §8) — applies to
  *responders*, not clients. The application is on the hook.
- **Goodbye / TTL=0 announcements** (§10.1) — same.
- **Continuous monitoring** — the client is a one-shot lookup, not a
  long-lived subscription. RFC 8765 (DNS Push) is the right tool for
  that.
- **Server side.** A `MdnsServer` is a natural follow-up; this commit
  only ships the client.