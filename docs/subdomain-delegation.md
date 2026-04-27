# Subdomain delegation — DNS structure with NS records

You bought `example.com` from a registrar. Now you want
`lab.example.com` (or any other slice of the namespace) to be served by
*your own* nameserver — a dns2ts process you run on your hardware, your
cloud VM, or your kitchen Raspberry Pi. This is **delegation**, and it's
how the DNS namespace gets carved up between operators.

This guide is about the structure you need to put in place: the records
that tell the rest of the world to ask *your* server for *your*
subdomain.

## The big picture — DNS as a tree of cuts

DNS is a hierarchical name space, but the *administrative* shape mirrors
the tree: every cut in the tree is a delegation point where authority
changes hands.

```
                        .  (root, run by IANA / 12 root server operators)
                        |
        ┌───────────────┴───────────────┐
       .com                           .org                ← TLDs
        |                               |                  (run by registries)
   ┌────┴────┐                          .
example.com  google.com                 .                ← second-level
        |                                                   (you bought this)
   ┌────┴────┐
   www       lab                                         ← you delegate
              |                                             this further
        ┌─────┴──────┐
        ns1          www                                 ← lab's own zone
                                                          (your dns2ts server)
```

Each horizontal line is a **delegation cut**. Above the cut, the parent
zone says "I'm not authoritative for what's below — go ask these
nameservers." That "go ask" is encoded as an `NS` record.

## NS records: the only thing the parent says about you

An NS record at `example.com.` says "if you want answers about
`example.com.` or anything under it, ask these nameservers":

```
$ dig example.com NS
example.com.    172800  IN  NS  a.iana-servers.net.
example.com.    172800  IN  NS  b.iana-servers.net.
```

These records appear in **two places**, and that's the part that trips
up most first-time operators:

1. **In the parent zone** — the `.com.` zone holds the NS records that
   tell the world where `example.com.` is hosted. You don't write these
   yourself; you submit them to your registrar, who pushes them to the
   `.com.` registry.
2. **In the apex of the child zone** — your own server, when asked
   `example.com. IN NS`, returns the same set.

Both sets must agree. The parent's set is authoritative for the
*delegation* (where to go); your set is authoritative for the zone's own
NS RRset (what's there). A mismatch is called **lame delegation** and
causes intermittent failures — some resolvers will trust one source,
some the other.

## Walk-through — delegate `lab.example.com` to a dns2ts server

You own `example.com`. You want `lab.example.com` to be served by a
dns2ts process running at `198.51.100.7` on UDP/TCP port 53. The
nameserver's hostname will be `ns1.example.com` (an A record under your
existing zone).

This is the **easy case** — your nameserver lives outside the zone
you're delegating, so no glue is needed.

### Step 1 — Run the authoritative server

Build a `Zone` from a master file and dispatch on the question:

```ts
import {readFileSync} from 'fs';
import {DnsServer, Zone, Packet, PacketTypes} from 'dns2ts';

const zone = Zone.fromZoneFile(readFileSync('lab.example.com.zone', 'utf8'));

const server = new DnsServer({
  udp: true,
  tcp: true,
  handle: (request, send) => {
    const q = request.questions[0];
    const response = Packet.createResponseFromRequest(request);
    response.questions = request.questions.slice();
    response.header.aa = 1;

    const matching = zone.records.filter((r) =>
      r.name.toLowerCase() === q.name.toLowerCase() &&
      (r.packetType.type === q.type || q.type === PacketTypes.ANY));

    if (matching.length === 0) {
      response.header.rcode = 3;            // NXDOMAIN
    } else {
      response.answers = matching;
    }

    send(response);
  },
});

await server.listen({udp: 53, tcp: 53});
```

Your zone file (`lab.example.com.zone`):

```dns
$ORIGIN lab.example.com.
$TTL 3600

@   IN SOA ns1.example.com. admin.example.com. (
        2024010101  ; serial
        7200        ; refresh
        3600        ; retry
        1209600     ; expire
        3600 )      ; minimum

@   IN NS  ns1.example.com.
www IN A   192.0.2.10
api IN A   192.0.2.11
```

The SOA record is mandatory — without it, your server isn't claiming
authority. The `admin` field is the responsible-party email with the
`@` replaced by a `.` (so `admin@example.com` becomes
`admin.example.com.`).

### Step 2 — Tell the parent zone

In the `example.com.` zone (managed at your registrar or DNS host), add
an NS record for the `lab` subdomain:

```dns
lab     IN NS  ns1.example.com.
```

How exactly you add this depends on where `example.com.` lives:

- **Registrar with a control panel** (Cloudflare, Namecheap,
  GoDaddy…) — find "Add Record", pick type NS, name `lab`, value
  `ns1.example.com.`. Save.
- **Self-hosted parent zone with dns2ts** — edit your `example.com.`
  zone file and `NotifyClient.request(...)` your secondaries.
- **API-driven hosts** (Route 53, Cloudflare API…) — POST the NS record
  via their API.

### Step 3 — Verify

Three checks, run in order:

```
$ dig +trace lab.example.com NS
```

Walks from the root through `.com.` to the parent zone and shows each
delegation cut. The bottom of the trace must list **your** ns1 entry.

```
$ dig @ns1.example.com lab.example.com SOA
```

Talks **directly** to your nameserver. The `aa` flag in the answer
header should be set, and the SOA serial should be what you wrote.

```
$ dig lab.example.com NS @8.8.8.8
```

Asks a public recursor. Should match Step 2 (after parent-zone TTL has
elapsed, typically 1-2 days).

If all three agree, the delegation is live.

## When you need glue records

If your nameserver's name lives **inside** the zone you're delegating —
e.g. `lab.example.com` is delegated to `ns1.lab.example.com.` — there's
a chicken-and-egg problem. To resolve `ns1.lab.example.com.`, a resolver
needs to ask the `lab.example.com.` nameservers; to find those it needs
to resolve `ns1.lab.example.com.`.

The fix is **glue records**: A/AAAA records for the in-bailiwick
nameserver placed in the *parent* zone alongside the NS record. They
break the cycle by giving resolvers an immediate IP.

```dns
;; in the example.com. zone:
lab        IN NS  ns1.lab.example.com.
ns1.lab    IN A   198.51.100.7              ; <-- glue
ns1.lab    IN AAAA 2001:db8::7              ; <-- glue v6
```

Most registrar UIs call this a **host record**, **child nameserver**,
or **registered glue**. Typically you have to register the host name
under your domain before it's accepted as a delegation target — the
registrar then submits the glue upstream.

Glue is *only* needed when the nameserver name is in-bailiwick. If
`lab.example.com` is delegated to `ns1.example.com` or
`ns.someoneelse.com`, those names resolve independently and no glue is
required.

## Two or more nameservers

Production delegations should list **at least two** nameservers (RFC
2182), preferably on different networks, so your zone stays resolvable
when one server or its uplink goes down.

```dns
;; in example.com.:
lab IN NS ns1.example.com.
lab IN NS ns2.example.com.
```

The two servers don't need to be in the same datacenter — many
operators run a primary at home/their VPS and a secondary on a
different cloud, hooked together via [AXFR](axfr.md) /
[IXFR](ixfr.md), with the primary firing [NOTIFY](notify.md) on every
change:

```ts
import {NotifyClient} from 'dns2ts';

// On the primary, after a zone change:
const notify = NotifyClient.request({dns: 'ns2.example.com', port: 53});
await notify('lab.example.com');
// → ns2 receives NOTIFY, requests SOA, sees a higher serial, runs IXFR.
```

The secondary needs to be authoritative for the same zone, with its own
`Zone` populated by an AXFR pulled from the primary. Authenticate the
transfer with [TSIG](tsig.md) or restrict by source IP.

## Sub-delegation — handing parts of *your* subdomain to others

Once you serve `lab.example.com.`, you can delegate further. Add NS
records inside *your* zone for the cut you're handing over:

```dns
;; in lab.example.com:
team        IN NS   ns1.team.lab.example.com.
ns1.team    IN A    198.51.100.42              ; in-bailiwick → glue
```

The team running `team.lab.example.com.` then has full authority over
that subtree without needing your involvement — they run their own
dns2ts (or other) authoritative server, return their own NS RRset at
their apex, and can sub-delegate further if they want to.

The same rules apply at every cut: NS records in the parent, glue if
in-bailiwick, consistent NS RRset in the child.

## Verification cheatsheet

After every delegation change, run these four:

| Command                                                | Tells you                                                                    |
| ------------------------------------------------------ | ---------------------------------------------------------------------------- |
| `dig +trace lab.example.com NS`                        | Walks root → TLD → parent → child; shows where it breaks if it does          |
| `dig @ns1.example.com lab.example.com SOA`             | Direct talk to your auth server (look for the `aa` flag in the response)     |
| `dig lab.example.com NS @1.1.1.1`                      | What a public recursor sees right now                                        |
| `dig AXFR lab.example.com @ns1.example.com`            | If your secondary IP is allowed, fetches the full zone (otherwise REFUSED)   |

If `+trace` shows the parent's NS RRset but the child gets `SERVFAIL`,
your server is unreachable, broken, or refusing the question. If the
direct query works but `+trace` fails, the parent's delegation isn't in
place yet (registrar UI says it is, but propagation takes time).

## Common pitfalls

- **Lame delegation** — the parent's NS RRset points at a host that
  isn't authoritative (or doesn't even run a DNS server on port 53).
  Symptom: intermittent `SERVFAIL` depending on which nameserver the
  recursor picked. Fix: align both NS sets and verify the host actually
  answers.

- **Missing glue** — in-bailiwick NS without a glue A/AAAA record in
  the parent. Symptom: `dig +trace` hangs at the cut and resolvers
  silently fall back to NXDOMAIN. Fix: register the glue at your
  registrar.

- **Wildcards don't cross cuts** — `*.example.com` in the parent zone
  does **not** cover names under a delegated subzone. Once
  `lab.example.com.` is delegated, the parent's wildcard is invisible
  there. If you want a wildcard for `*.lab.example.com`, put it in the
  child zone.

- **Mismatched SOA across primaries** — if you run multiple primaries
  (e.g. anycast), make sure each one pulls from the same source of
  truth. Two primaries with different SOA serials cause secondaries to
  oscillate between them.

- **TTL surprise on delegation changes** — the parent's NS records
  typically have a TTL of 1-2 days. A "fresh" delegation propagates as
  fast as that TTL drains from caches around the world. Plan changes
  ahead; lower the parent NS TTL a couple of days *before* moving the
  delegation, then raise it again afterward.

- **NS pointing at a CNAME** — RFC 2181 §10.3 forbids this; the target
  of an NS record must be a name with an A/AAAA, not a CNAME. Most
  servers reject it; some misbehave silently. Just don't.

## Beyond basic delegation

Once your delegation is stable, the standard next layers:

- [**AXFR / IXFR / NOTIFY**](axfr.md) — primary → secondary replication
  so you can run multiple servers without copy-pasting zone files.
- [**TSIG**](tsig.md) — authenticate every server-to-server hop (NOTIFY,
  AXFR, dynamic UPDATE) with a shared HMAC key.
- [**Dynamic UPDATE**](update.md) — let an automation pipeline (CI,
  certbot, k8s controller, …) write records into the zone without
  editing zone files by hand.
- **DNSSEC** — cryptographic authentication of the delegation chain
  (DS record in the parent, DNSKEY/RRSIG/NSEC3 in the child). Not yet
  implemented in this library, but the standard hardening once your
  authoritative setup is solid.

## Split-horizon and internal-only subdomains

A common pattern: `internal.example.com` resolves to private addresses
inside your network, but doesn't exist in public DNS at all. The trick
is to delegate it **only inside your network**:

- **Don't** add NS records for `internal` to the public parent zone.
- Configure your **internal recursor** with a stub or forward zone
  pointing at your internal dns2ts server.

Public DNS continues to know nothing about the subdomain (NXDOMAIN for
outsiders); your internal recursor sees the delegation and forwards
queries to your auth server.

For a single dns2ts process that serves both public and private views,
use the per-request hooks (see [DNS servers](dns-servers.md)) to
dispatch on the source IP.

## A complete worked example

Operator owns `example.com.` at a registrar. They run their primary
nameserver `ns1.example.com.` (`198.51.100.7`) on a VPS and a secondary
`ns2.example.com.` (`198.51.100.8`) on a different provider. They want
`lab.example.com.` served by both, with NOTIFY → IXFR replication.

**1. In the public parent zone** (managed at the registrar):

```dns
ns1     IN A   198.51.100.7
ns2     IN A   198.51.100.8

lab     IN NS  ns1.example.com.
lab     IN NS  ns2.example.com.
```

(No glue needed: `ns1.example.com.` is not under `lab.example.com.`.)

**2. The primary's zone file** (`lab.example.com.zone`):

```dns
$ORIGIN lab.example.com.
$TTL 3600
@   IN SOA ns1.example.com. admin.example.com. (
        2024010101 7200 3600 1209600 3600 )
@   IN NS  ns1.example.com.
@   IN NS  ns2.example.com.
www IN A   192.0.2.10
api IN A   192.0.2.11
```

**3. The primary's dns2ts process** dispatches normal queries from the
`Zone`, AXFR queries via `Zone.toAxfrPackets`, and IXFR via
`Zone.toIxfrPackets` (with a small in-memory journal of recent change
sets). After every zone edit, it fires NOTIFY at `ns2.example.com.`.

**4. The secondary's dns2ts process** is configured with the primary's
hostname; when it receives a NOTIFY for `lab.example.com.` it runs an
IXFR against the primary, applies the diff to its local `Zone`, and
serves authoritative answers from the result.

**5. Verification**:

```
$ dig +trace lab.example.com SOA      # walks the delegation
$ dig @ns2.example.com lab.example.com SOA serial   # secondary in sync
$ dig www.lab.example.com @1.1.1.1     # public recursor
```

That's the whole picture: parent zone delegation, paired primaries
with replication, public verifiability.

## Related

- [DNS servers](dns-servers.md) — running the authoritative server.
- [Zone files](zone-files.md) — master file format the `Zone` is loaded
  from.
- [AXFR](axfr.md), [IXFR](ixfr.md), [NOTIFY](notify.md) — primary →
  secondary replication.
- [DNS UPDATE](update.md) — programmatic record changes.
- [TSIG](tsig.md) — authenticate the server-to-server channels.
- [Reverse proxy](reverse-proxy.md) — fronting the auth server with
  nginx / HAProxy / Envoy for TLS, rate limiting, IP transparency.
- [Security hardening](security-hardening.md) — 0x20 randomization and
  bailiwick filtering for the resolver path.