# IXFR — incremental zone transfer (RFC 1995)

IXFR is the smaller sibling of [AXFR](axfr.md): instead of shipping the
entire zone every refresh, the secondary tells the primary "I'm at
serial N — what changed?" and the primary sends only the diff.

The exchange runs over TCP (or TLS), like AXFR. Three response shapes are
possible (RFC 1995 §2):

1. **No-change** — secondary is already current. Primary replies with one
   message containing a single SOA.
2. **Incremental** — primary has the change history and answers with one
   message that walks the SOA from `clientSerial` up to current,
   alternating delete-blocks and add-blocks.
3. **AXFR fallback** — primary has no usable history (e.g. lost its
   journal across a restart) and instead sends the full zone in the same
   shape as [AXFR](axfr.md).

dns2ts implements both halves: a `Zone.toIxfrPackets()` server helper
that picks the right response shape, and an `IxfrClient` that classifies
the response into a discriminated union.

## Server side — answering IXFR

`Zone.toIxfrPackets(query, options?)` does the dispatch for you. Pass it
the parsed query (which carries the client's current SOA in the
AUTHORITY section per RFC 1995 §3) and an optional ordered list of
`ZoneChangeSet` entries:

```ts
import {DnsServer, Zone, PacketTypes} from 'dns2ts';

const zone = Zone.fromZoneFile(/* … */);

// Journal of changes the primary has on hand. Each entry walks one
// serial increment (fromSerial → toSerial). Adjacent entries must chain:
// history[i].toSerial === history[i+1].fromSerial.
const history = [
  {
    fromSerial: 1,
    toSerial: 2,
    fromSoa: soaResourceAt(1),
    toSoa:   soaResourceAt(2),
    deletions: [/* removed records at serial 1 */],
    additions: [/* added records at serial 2 */],
  },
  // … more entries as the zone evolves …
];

const server = new DnsServer({
  tcp: true,
  handle: (request, send) => {
    if (request.questions[0]?.type === PacketTypes.IXFR) {
      send(zone.toIxfrPackets(request, {history: history}));
      return;
    }

    if (request.questions[0]?.type === PacketTypes.AXFR) {
      send(zone.toAxfrPackets(request));
      return;
    }

    // … normal A/AAAA/MX/… handling …
  },
});

await server.listen({tcp: 53});
```

`toIxfrPackets` decides automatically:

| Condition                                         | Response shape         |
| ------------------------------------------------- | ---------------------- |
| `clientSerial === currentSerial`                  | no-change (single SOA) |
| history chains contiguously from client → current | incremental            |
| no chain found (or no SOA in authority)           | AXFR fallback          |

If you don't keep history, IXFR queries always fall back to AXFR — that
is RFC-compliant and is exactly what BIND does after a journal corruption.
You can ship IXFR support gradually: start with no history (every IXFR is
an AXFR), then add a journal once you actually want bandwidth savings.

### Building `ZoneChangeSet` entries

Each change set is the diff that takes the zone from `fromSerial` to
`toSerial`:

- `fromSoa` / `toSoa` — full `PacketResource` instances. The SOA at
  `fromSerial` is what the primary places before the deletions; the SOA
  at `toSerial` is what marks the end of the deletions / start of
  additions.
- `deletions` — records present at `fromSerial` that are gone at
  `toSerial`.
- `additions` — records present at `toSerial` that were not at
  `fromSerial`.

For most authoritative server use cases you compute these by diffing two
in-memory zone snapshots whenever the zone is rewritten, then prepend
the change set to the journal.

## Client side — `IxfrClient`

```ts
import {IxfrClient, ClientOptionsProtocol, SOA} from 'dns2ts';

const transfer = IxfrClient.request({
  dns: 'ns1.example.com',
  port: 53,
  // protocol: ClientOptionsProtocol.tls,        // for IXFR over DoT
});

const myCurrentSoa = new SOA(
  'ns1.example.com', 'admin.example.com', 1,    // serial we currently have
  7200, 3600, 1209600, 3600,
);

const result = await transfer('example.com', myCurrentSoa);

switch (result.type) {
  case 'noChange':
    console.log('already at the latest serial');
    break;

  case 'incremental':
    for (const diff of result.diffs) {
      console.log(`apply: ${diff.fromSerial} → ${diff.toSerial}`);
      console.log(`  deletions: ${diff.deletions.length}`);
      console.log(`  additions: ${diff.additions.length}`);
    }
    break;

  case 'fullAxfr':
    console.log(`primary fell back to full AXFR (${result.records.length} records)`);
    break;
}
```

The classifier reads the answer stream and picks the type from the SOA
framing — you don't have to do RFC-1995 parsing yourself. A malformed
stream (e.g. a missing closing SOA) raises an error rather than producing
a half-decoded result.

### Applying the diff to a local zone

```ts
import {Zone} from 'dns2ts';

const local = Zone.fromZoneFile(/* current state */);

if (result.type === 'incremental') {
  for (const diff of result.diffs) {
    // Drop deletions
    local.records = local.records.filter((r) =>
      !diff.deletions.some((d) => sameRR(d, r)));

    // Append additions
    local.records.push(...diff.additions);
  }
}
```

`sameRR` is your zone's record-equality predicate; the simplest is
"same name, type, class, TTL, and RDATA wire bytes".

## Combining IXFR and AXFR

A typical secondary uses NOTIFY → SOA-check → IXFR (with AXFR fallback)
in that order:

```ts
import {NotifyClient, IxfrClient, AxfrClient, PacketTypes, PacketOpcode} from 'dns2ts';

// 1) Receive NOTIFY (see notify.md)

// 2) Re-query the SOA to confirm
const soaResolver = TCPClient.request({dns: primary, port: 53});
const soaResp = await soaResolver(zoneName, PacketTypes.SOA, PacketClass.IN);
const currentPrimarySerial = (soaResp.answers[0].packetType as SOA).serial;

if (currentPrimarySerial === ourSerial) return;     // nothing to do

// 3) Try IXFR
const ixfr = IxfrClient.request({dns: primary, port: 53});
const result = await ixfr(zoneName, ourCurrentSoa);

if (result.type === 'incremental') {
  applyDiffs(result.diffs);
} else if (result.type === 'fullAxfr') {
  // Either we asked too far back, or the primary has no journal.
  replaceZone(result.records);
} else {
  // We were already at the latest serial — typically because somebody
  // else NOTIFY'd us first and we already refreshed.
}
```

In practice: maintain a local journal alongside the zone, update both
atomically, and replay the diff before persisting.

## Authentication

IXFR uses the same authentication story as AXFR: nothing built into the
protocol, so layer one of:

- **IP allow-list** of secondary IPs at the handler level
- **TSIG** on the IXFR query and response — see [TSIG](tsig.md)
- **DoT** with mutual TLS (`requestCert: true` in the TLS server options)

Pair these with the same defenses on AXFR to keep the fallback path safe.

## What's not yet implemented

- **Multi-message IXFR** — like AXFR, the response is a single message
  for now. Very large diffs would have to be split by the caller.
- **Condensation across multiple changes** — RFC 1995 lets you collapse
  several change sets into one diff if they touch the same RRs. dns2ts
  emits each `ZoneChangeSet` as its own diff sequence; if you want
  condensation, do it before adding entries to `history`.
- **Server-side journal storage** — `Zone` doesn't persist history
  between restarts. Snapshot to disk and restore on boot if you care
  about that.

## Related

- [Zone files](zone-files.md) — load the zone the IXFR is happening on.
- [AXFR](axfr.md) — the fallback path and the protocol IXFR derives from.
- [NOTIFY](notify.md) — the trigger that starts an IXFR cycle in
  practice.
- [TSIG](tsig.md) — authenticate the exchange.