# Becoming a TLD — what's actually involved

A TLD (Top-Level Domain) is the rightmost label of a public DNS name —
`.com`, `.org`, `.de`, `.example`. Being a TLD operator means having
your zone delegated **directly from the root zone**: the root operators
publish NS records for your TLD, the global DNS routes queries to your
nameservers, and registrars sell second-level names under it.

If you arrived here thinking "I'll set up my own dns2ts server and call
it a TLD" — the technical part is solvable. The much larger part is
policy, money, and a multi-year process run by ICANN. This guide is
honest about what's required, what alternatives exist, and where this
library actually fits in.

## TL;DR

| What you want                                 | What it costs                                | How long                |
| --------------------------------------------- | -------------------------------------------- | ----------------------- |
| A new public **gTLD** (e.g. `.bank`, `.shop`) | $230k+ application + ongoing fees + ops      | 2-3+ years via ICANN    |
| A new **ccTLD**                               | Practically not available                    | —                       |
| A **Special-Use** TLD via IETF RFC            | Time and rough consensus                     | 1-3 years through IETF  |
| A **private / alternative root** TLD          | Just run a root nameserver                   | hours                   |
| A useful subdomain people can use             | A second-level domain you already have       | hours (see below)       |

## Five categories of TLD — and which paths exist today

Not every TLD is created the same way. The path you can take depends on
which kind you're after.

### 1. gTLDs — generic Top-Level Domains

`.com`, `.net`, `.org`, plus the ~1,200 strings added in ICANN's 2012
"New gTLD Program" round (`.app`, `.bank`, `.shop`, `.berlin`, `.xyz`,
`.guru`, …). This is the path most people imagine when they say "be a
TLD."

- **Authority**: ICANN
  ([icann.org](https://www.icann.org/))
- **Process**: ICANN New gTLD Program
  ([newgtlds.icann.org](https://newgtlds.icann.org/))
- **Status**: Round 2 ("Subsequent Procedures") is being prepared by
  ICANN. The 2012 round closed long ago; the next application window
  is expected around 2026 (subject to ICANN's policy work).
- **Application fee**: $230,000+ in the 2026 round, plus legal,
  technical, and ongoing operations costs.
- **Time**: 2–3+ years from application to delegation, longer if your
  string lands in a contention set with other applicants.

### 2. ccTLDs — country-code Top-Level Domains

`.de`, `.uk`, `.jp`, etc. The list is fixed by **ISO 3166-1 alpha-2**:
two-letter country codes. New ccTLDs only appear when ISO adds a new
country or territory code (rare).

- **Authority**: IANA delegates each ccTLD to a country-designated
  operator under [RFC 1591](https://datatracker.ietf.org/doc/html/rfc1591).
- **List**: [IANA Root Zone Database](https://www.iana.org/domains/root/db)
- **Practical availability**: zero unless you're the designated
  operator for a new ISO 3166-1 country code.

### 3. Special-Use TLDs — IETF reserved names

Names reserved at the protocol level for non-public use:

- `.local` — mDNS service discovery on the LAN
  ([RFC 6762](https://datatracker.ietf.org/doc/html/rfc6762))
- `.localhost` — loopback
  ([RFC 6761 §6.3](https://datatracker.ietf.org/doc/html/rfc6761#section-6.3))
- `.example`, `.test`, `.invalid` — documentation and testing
  ([RFC 2606](https://datatracker.ietf.org/doc/html/rfc2606))
- `.onion` — Tor hidden services
  ([RFC 7686](https://datatracker.ietf.org/doc/html/rfc7686))
- `.home.arpa` — homenet
  ([RFC 8375](https://datatracker.ietf.org/doc/html/rfc8375))
- `.alt` — alternative-resolution names
  ([RFC 9476](https://datatracker.ietf.org/doc/html/rfc9476))

These are not in the public DNS root. Resolvers and applications are
required (or at least encouraged) to handle them locally.

- **Authority**: IETF, via the standards process
  ([ietf.org/standards/process](https://www.ietf.org/standards/process/))
- **Registry**: [IANA Special-Use Domain Names](https://www.iana.org/assignments/special-use-domain-names/special-use-domain-names.xhtml)
- **Process**: write an Internet-Draft, get it adopted by a working
  group, achieve rough consensus, publish as an RFC ("the IETF
  consensus process"). Practically: 1–3 years and several hundred
  pages of mailing-list discussion. The IESG has been conservative
  about adding new special-use names.

This is the closest thing to "free" — no money, no ICANN, no annual
ops fees — but the path is policy-heavy and only justified if you have
a genuine protocol need (Tor, mDNS, etc.). It's not a way to "claim a
TLD" for branding.

### 4. Private / internal roots — your own DNS root

You can run your own root zone for an internal network and put any TLD
under it. From the perspective of resolvers configured to use *your*
root, your TLD exists; from the public Internet's perspective, it
doesn't.

- **Authority**: nobody — it's your network.
- **Risk**: if a string you picked later becomes a real public gTLD,
  every host in your network will hit a name collision. ICANN tracks
  this under "Name Collision Mitigation"
  ([icann.org/resources/pages/name-collision](https://www.icann.org/resources/pages/name-collision-2013-12-06-en)).
  Use one of the IETF-reserved special-use names (`.internal` was
  reserved by ICANN as an internal-use TLD in 2024 specifically for
  this — see [ICANN announcement](https://www.icann.org/en/announcements/details/icann-board-resolution-on-internal-tld-25-02-2024-en))
  and you avoid the collision risk.
- **Use case**: enterprise internal networks; the `.corp`, `.home`,
  `.lan`, `.mail`, `.internal` cluster.

This is genuinely doable as a software project. With dns2ts, see
[DNS servers](dns-servers.md) for running an authoritative server, and
configure your network's recursors with a stub or forward zone for the
internal TLD.

### 5. Alternative DNS roots

A separate DNS root, run independently of the IANA root, with its own
TLDs. Examples: OpenNIC, Namecoin, Handshake. Resolution of those TLDs
only works for clients that have explicitly configured the alternative
root.

- **Reach**: limited to communities that opt in.
- **Conflict**: an alternative root might create a TLD that later
  becomes a public gTLD; same collision risk as private roots.

Practical for niche communities; not a path to widespread reachability.

## The ICANN gTLD path — phases in detail

For the only category where you can actually buy your way into the
public DNS root.

### 1. Pre-application

Decide on the string, the business model, the registry policies. ICANN's
**Applicant Guidebook** is the canonical reference; the 2012 version
runs over 350 pages.

- 2012 Applicant Guidebook (historical):
  [newgtlds.icann.org/en/applicants/agb](https://newgtlds.icann.org/en/applicants/agb)
- Subsequent Procedures (2026 round): track via
  [ICANN GNSO SubPro](https://gnso.icann.org/en/group-activities/active/new-gtld-subsequent-procedures)

### 2. Application

You submit detailed financial, technical, and operational plans to
ICANN. The application is evaluated against the Guidebook's criteria.

- Application fee: ~$185k-$230k+ (round-dependent).
- Evaluation period: 6-12 months for "straightforward" applications,
  much longer for contested ones.
- Output: pass/fail at multiple gates (string review, financial
  evaluation, technical evaluation, geographic-name reviews, etc.).

### 3. Contention resolution

If multiple applicants want the same string (e.g. five companies all
applied for `.cloud`), they're put in a "contention set" and resolved
via:

- Mutual agreement (the most common path — applicants negotiate; one
  buys out the others or they form a joint venture).
- Community priority evaluation (if one is a defined community
  applicant).
- Auction of last resort (highest bid wins). Some 2012-round auctions
  cleared at $25M-$135M for popular strings.

### 4. Pre-Delegation Testing (PDT)

Before ICANN delegates the TLD into the root zone, your nameservers
have to pass a battery of automated tests covering:

- DNS server compliance (RFC conformance, response correctness,
  EDNS, IPv6, …)
- DNSSEC signing and chain validity
- WHOIS / RDAP service availability
- EPP service for registrars
- Data Escrow integration

ICANN PDT specs:
[icann.org/resources/pages/pdt](https://www.icann.org/resources/pages/registries/pdt-2012-02-25-en)

This is the part where dns2ts is technically relevant. Your library or
registry stack must pass conformance testing — performance, EDNS, IPv6,
TCP fallback, NOTIFY, AXFR, IXFR, DNSSEC. dns2ts covers most of those
([this library's roadmap](../README.md#documentation) lists the gaps —
DNSSEC validation/signing is the main missing piece you'd need).

### 5. Registry Agreement and delegation

You sign the **Base Registry Agreement** with ICANN, IANA delegates
your TLD into the root zone, and you're operational.

- Base Registry Agreement:
  [icann.org/resources/pages/registries/registries-agreements-en](https://www.icann.org/resources/pages/registries/registries-agreements-en)
- IANA root zone change procedure:
  [iana.org/help/root-zone-management](https://www.iana.org/help/root-zone-management)

## Ongoing technical requirements as a registry operator

Even after delegation, you continue to be subject to operational
requirements defined in the Base Registry Agreement's specifications.
The major ones:

### Specification 6 — Registry Performance Specifications

Uptime, RTT, and operational metrics enforced by ICANN.

- DNS service: 100% availability (yes, really — measured monthly,
  with very small downtime budget).
- DNS resolution RTT: ≤ 500 ms UDP, ≤ 1500 ms TCP, 95th percentile.
- WHOIS / RDAP: ≥ 98% availability, RTT ≤ 2 s.
- EPP: ≥ 99.4% availability.

This drives the multi-region anycast architecture every TLD operator
uses. See:

- [RFC 7094](https://datatracker.ietf.org/doc/html/rfc7094) — anycast
  architectural considerations.
- [RFC 7720](https://datatracker.ietf.org/doc/html/rfc7720) — DNS root
  name service protocol requirements.

### Specification 4 — Registration Data Directory Services (WHOIS / RDAP)

You expose registration data via WHOIS (legacy, port 43) and RDAP
(modern, HTTP-based).

- RDAP RFCs: [RFC 7480](https://datatracker.ietf.org/doc/html/rfc7480),
  [RFC 7481](https://datatracker.ietf.org/doc/html/rfc7481),
  [RFC 9082](https://datatracker.ietf.org/doc/html/rfc9082),
  [RFC 9083](https://datatracker.ietf.org/doc/html/rfc9083).
- ICANN RDAP profile:
  [icann.org/rdap](https://www.icann.org/resources/pages/rdap-2017-04-15-en)

### EPP — Extensible Provisioning Protocol

Registrars register / transfer / renew names under your TLD via EPP.
You must run an EPP server for them to talk to.

- Core EPP: [RFC 5730](https://datatracker.ietf.org/doc/html/rfc5730)
- Domain mapping: [RFC 5731](https://datatracker.ietf.org/doc/html/rfc5731)
- Host mapping: [RFC 5732](https://datatracker.ietf.org/doc/html/rfc5732)
- Contact mapping: [RFC 5733](https://datatracker.ietf.org/doc/html/rfc5733)
- Transport over TCP: [RFC 5734](https://datatracker.ietf.org/doc/html/rfc5734)
- ICANN EPP extensions:
  [icann.org/resources/pages/epp-extensions](https://www.icann.org/resources/pages/registries/epp)

This is its own protocol stack, separate from DNS — dns2ts is not
involved here.

### Specification 2 — Data Escrow

You must escrow your registry data with a third-party agent
(NCC Group, Iron Mountain, EBRP), so the data survives company
failure. Daily incremental, weekly full deposits. ICANN audits this.

- Data Escrow specs:
  [icann.org/resources/pages/escrow-agreement](https://www.icann.org/resources/pages/registries/registries-agreements-en)

### DNSSEC signing

The TLD zone must be signed and the DS record submitted to IANA for
publication in the root.

- DNSSEC core: [RFC 4033](https://datatracker.ietf.org/doc/html/rfc4033),
  [RFC 4034](https://datatracker.ietf.org/doc/html/rfc4034),
  [RFC 4035](https://datatracker.ietf.org/doc/html/rfc4035).
- NSEC3 (preferred for TLDs to defeat zone walking):
  [RFC 5155](https://datatracker.ietf.org/doc/html/rfc5155).
- Operational practices: [RFC 6781](https://datatracker.ietf.org/doc/html/rfc6781).

dns2ts currently parses DNSKEY/DS/RRSIG/NSEC/NSEC3 records but does not
sign or validate them. A TLD operator using this library would need to
add DNSSEC signing — that's the largest remaining gap in the roadmap
([roadmap progress](../README.md#documentation) tracks it).

### Trademark Clearinghouse (TMCH)

For any new gTLD: you integrate with the global TMCH for sunrise and
trademark claims periods.

- TMCH: [trademark-clearinghouse.com](https://www.trademark-clearinghouse.com/)

### Centralized Zone Data Service (CZDS)

You publish your zone file to ICANN's CZDS so security researchers and
others can request access.

- CZDS: [czds.icann.org](https://czds.icann.org/)

## What dns2ts can and can't do for a TLD operator

**Can**:

- Serve authoritative DNS responses for the TLD zone (the core protocol
  requirement). The library handles UDP, TCP, DoT (RFC 7858), DoH (RFC
  8484), with EDNS support including Cookies (RFC 7873) and Padding
  (RFC 7830).
- Run primary/secondary replication via [AXFR](axfr.md),
  [IXFR](ixfr.md), and [NOTIFY](notify.md) — exactly what you'd run
  between geographically diverse anycast nodes.
- Take dynamic updates via [DNS UPDATE](update.md) — useful for the
  EPP→DNS bridge (your EPP server processes registrar requests, then
  pushes the resulting RR changes into the auth servers via UPDATE).
- Pass conformance for many of the PDT tests around UDP/TCP framing,
  EDNS handling, NOTIFY/AXFR/IXFR mechanics.
- Handle [PROXY protocol](proxy-protocol.md) and [reverse-proxy
  fronting](reverse-proxy.md) for IP transparency through anycast load
  balancers.
- Authenticate inter-server channels with [TSIG](tsig.md).

**Can't (yet)**:

- **DNSSEC signing/validation**. Required by all modern TLD operators.
  This is the single biggest gap.
- **EPP**, **WHOIS**, **RDAP** — separate protocol stacks; out of
  scope for this library. You'd integrate one of the existing open-
  source registry stacks (FRED from CZ.NIC, CoCCA, Verisign's
  proprietary stack equivalents).
- **Data Escrow** — operational concern; you'd integrate with an
  escrow agent's API.
- **High-volume registry operations** — millions of records, complex
  policy enforcement. dns2ts handles ~1700 encodes/s of representative
  packets after the perf refactor; that's enough for many small
  TLDs, but a top-100 TLD would push you onto a more specialized stack
  (Knot, NSD, BIND with auth-only mode) for raw throughput.

## Realistic alternatives most "I want my own TLD" goals can use instead

If the underlying goal is "I want a memorable namespace I control,"
the answer is almost never "become a TLD." It's:

### Subdomain delegation under a domain you own

Buy `example.com` for $10/year, run your own auth server for
`*.example.com`, and let people register `whatever.example.com`
under your zone. This is what `.tk`, `.ml`, free-DNS providers, and
many SaaS products effectively do.

See [subdomain delegation](subdomain-delegation.md) for the full
walkthrough.

### Internal-only TLD on a private root

Run a private root in your enterprise network with `.internal` (now
ICANN-reserved exactly for this purpose) or another reserved name.
Public DNS doesn't know about it; your network does.

### Special-use name through IETF if there's a real protocol need

If you're inventing a new naming protocol (the way `.onion` is part of
Tor), the IETF special-use process is the right one. It's slow, but
it's free and produces a name that's universally reserved against
collision.

### Private label registry under an existing TLD operator

Several TLD operators (Donuts, GoDaddy Registry, etc.) offer "registry
services" — they handle the technical operation while you brand and
market a sub-portion of an existing TLD. Cheaper than running your own.

## Reference list

### ICANN

- ICANN home: [icann.org](https://www.icann.org/)
- New gTLD Program: [newgtlds.icann.org](https://newgtlds.icann.org/)
- Subsequent Procedures (2026 round prep):
  [gnso.icann.org/en/group-activities/active/new-gtld-subsequent-procedures](https://gnso.icann.org/en/group-activities/active/new-gtld-subsequent-procedures)
- Registry agreements:
  [icann.org/resources/pages/registries/registries-agreements-en](https://www.icann.org/resources/pages/registries/registries-agreements-en)
- Compliance: [icann.org/compliance](https://www.icann.org/compliance)
- Pre-Delegation Testing:
  [icann.org/resources/pages/pdt-2012-02-25-en](https://www.icann.org/resources/pages/registries/pdt-2012-02-25-en)
- Name Collision program:
  [icann.org/resources/pages/name-collision-2013-12-06-en](https://www.icann.org/resources/pages/name-collision-2013-12-06-en)

### IANA

- Root Zone Management:
  [iana.org/domains/root](https://www.iana.org/domains/root)
- Root Zone Database (every TLD currently delegated):
  [iana.org/domains/root/db](https://www.iana.org/domains/root/db)
- Special-Use Domain Names registry:
  [iana.org/assignments/special-use-domain-names](https://www.iana.org/assignments/special-use-domain-names/special-use-domain-names.xhtml)

### Trademark Clearinghouse

- TMCH: [trademark-clearinghouse.com](https://www.trademark-clearinghouse.com/)

### Centralized Zone Data Service

- CZDS: [czds.icann.org](https://czds.icann.org/)

### IETF / standards

- IETF process overview:
  [ietf.org/standards/process](https://www.ietf.org/standards/process/)
- DNSOP working group:
  [datatracker.ietf.org/wg/dnsop](https://datatracker.ietf.org/wg/dnsop/)

### Foundational RFCs

- [RFC 1591](https://datatracker.ietf.org/doc/html/rfc1591) — DNS
  structure and delegation (the philosophy)
- [RFC 2606](https://datatracker.ietf.org/doc/html/rfc2606) —
  Reserved Top Level DNS Names
- [RFC 6761](https://datatracker.ietf.org/doc/html/rfc6761) —
  Special-Use Domain Names
- [RFC 7720](https://datatracker.ietf.org/doc/html/rfc7720) — DNS
  Root Name Service Protocol Requirements
- [RFC 7706](https://datatracker.ietf.org/doc/html/rfc7706) — Running
  a Local Copy of the Root Zone
- [RFC 7094](https://datatracker.ietf.org/doc/html/rfc7094) — Anycast
  architectural considerations

### EPP — registrar protocol

- [RFC 5730](https://datatracker.ietf.org/doc/html/rfc5730) — EPP core
- [RFC 5731](https://datatracker.ietf.org/doc/html/rfc5731) — EPP
  domain mapping
- [RFC 5732](https://datatracker.ietf.org/doc/html/rfc5732) — EPP host
  mapping
- [RFC 5733](https://datatracker.ietf.org/doc/html/rfc5733) — EPP
  contact mapping
- [RFC 5734](https://datatracker.ietf.org/doc/html/rfc5734) — EPP
  transport over TCP

### RDAP — modern WHOIS

- [RFC 7480](https://datatracker.ietf.org/doc/html/rfc7480) — RDAP
  HTTP usage
- [RFC 7481](https://datatracker.ietf.org/doc/html/rfc7481) — RDAP
  security services
- [RFC 9082](https://datatracker.ietf.org/doc/html/rfc9082) — RDAP
  query format
- [RFC 9083](https://datatracker.ietf.org/doc/html/rfc9083) — JSON
  responses

### DNSSEC — required for TLD operators

- [RFC 4033](https://datatracker.ietf.org/doc/html/rfc4033) — DNSSEC
  introduction and requirements
- [RFC 4034](https://datatracker.ietf.org/doc/html/rfc4034) — DNSSEC
  resource records
- [RFC 4035](https://datatracker.ietf.org/doc/html/rfc4035) — DNSSEC
  protocol modifications
- [RFC 5155](https://datatracker.ietf.org/doc/html/rfc5155) — NSEC3
  (zone-walking-resistant denial of existence)
- [RFC 6781](https://datatracker.ietf.org/doc/html/rfc6781) — DNSSEC
  operational practices
- [RFC 7344](https://datatracker.ietf.org/doc/html/rfc7344) — automating
  the DS record submission

### Open-source registry stacks (for context)

- FRED — CZ.NIC's full registry stack:
  [fred.nic.cz](https://fred.nic.cz/)
- CoCCA — registry software used by several smaller TLDs:
  [cocca.org.nz](https://cocca.org.nz/)

### Alternative roots

- OpenNIC: [opennic.org](https://www.opennic.org/)
- Namecoin: [namecoin.org](https://www.namecoin.org/)
- Handshake: [handshake.org](https://handshake.org/)

## Honest summary

If you want to be a public TLD operator, this is a multi-year,
mid-six-figure-minimum business with regulatory and contractual
obligations. dns2ts can serve the actual DNS queries, and the
roadmap covers most of the protocol-side requirements once DNSSEC
signing lands — but the protocol piece is maybe 10% of the work.

If your real goal is "control a memorable namespace," nine times out of
ten the right answer is to register a normal second-level domain and
delegate subdomains under it
([subdomain delegation guide](subdomain-delegation.md)).

If your real goal is "internal-only namespace for our org," run a
private root or use the ICANN-reserved `.internal` TLD; dns2ts is a
fine fit for the auth server.

If you're working on a new naming protocol, the IETF special-use
process is your route — talk to the DNSOP working group.

## Related

- [Subdomain delegation](subdomain-delegation.md) — the practical
  alternative for almost every "I want my own TLD" goal.
- [DNS servers](dns-servers.md) — running the auth server itself.
- [Zone files](zone-files.md), [AXFR](axfr.md), [IXFR](ixfr.md),
  [NOTIFY](notify.md), [DNS UPDATE](update.md) — the building blocks
  for primary/secondary replication and EPP integration.
- [TSIG](tsig.md) — authenticate the server-to-server channels.
- [Reverse proxy](reverse-proxy.md) — front the auth server with
  nginx/HAProxy/Envoy for anycast LB and TLS termination.