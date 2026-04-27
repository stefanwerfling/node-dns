# Secure domain setup — desec.io for DNSSEC, email-security records, and delegation to your own dns2ts

This guide is the practical recipe for an operator who wants:

- **A domain with DNSSEC** without paying for a fancy hosting provider —
  using [desec.io](https://desec.io/) (free, donation-funded, run by
  Berlin-based Internet operators since 2017) as the parent
  authoritative service.
- **Modern email security** — SPF, DKIM, DMARC, MTA-STS, TLS-RPT, and
  optionally DANE/TLSA — done right via the parent zone.
- **A subdomain delegated to your own dns2ts authoritative server**, so
  you keep control over `*.lab.example.com` (or whatever you delegate)
  while the rest of `example.com` stays cleanly DNSSEC-signed at desec.

dns2ts doesn't sign zones with DNSSEC yet (the roadmap tracks it), but
that's fine for this setup — desec covers the parent and the
delegation to your child zone is an "insecure delegation," which
DNSSEC validators handle gracefully. When dns2ts gains signing later,
the upgrade path is one DS-record submission away.

## The architecture you're building

```
                  .  (root, signed)
                  |
                .com  (TLD, signed)
                  |
                example.com.   ← desec.io's nameservers, signed by desec
                ┌───┴────────────────┐
                │ apex records:      │
                │   MX, SPF, DMARC,  │
                │   MTA-STS, TLS-RPT │
                │   DKIM (selectors) │
                │   TLSA (if DANE)   │
                │   NS for sub →     │ ──── delegates to ────┐
                └────────────────────┘                       │
                                                             │
                                                             ▼
                                                lab.example.com.
                                                ┌────────────────┐
                                                │ your dns2ts    │
                                                │ authoritative  │
                                                │ server (your   │
                                                │ infrastructure)│
                                                └────────────────┘
```

The DNSSEC chain runs root → `.com` → desec's `example.com` zone
(signed). At the `lab` cut, the parent zone (still desec) publishes
NS records but **no DS record** — that means resolvers see "this
delegation is intentionally not signed," accept the child's answers
unsigned, and validation succeeds across the boundary. This is RFC
4035-conformant; it's how thousands of mixed-signed zones work in the
wild.

## Step 1 — register the domain

Buy `example.com` at any registrar that supports submitting **NS
records** and **DS records** for your domain (essentially all of them
do — Cloudflare Registrar, Namecheap, INWX, Porkbun, GoDaddy). For
DNSSEC to work end-to-end, you'll need the registrar to push a DS
record into the parent `.com.` zone — confirm they offer this in their
control panel before buying.

If you're not sure: go with INWX, Cloudflare, or Porkbun — all three
have working DS submission UIs.

## Step 2 — set up the desec.io zone

1. Sign up at [desec.io](https://desec.io/) (free, just an email).
2. **"Domains" → "Create a New Domain"** — enter `example.com`.
3. desec creates the zone with DNSSEC keys generated automatically.
   You don't manage keys; rotation, NSEC3, and re-signing are all
   handled by desec.

The zone now lives on desec's nameservers:

- `ns1.desec.io.`
- `ns2.desec.org.`

(Yes, two different parent TLDs — that's intentional resilience: if
something goes wrong with `.io.` or `.org.` operations, the other side
still resolves.)

desec also exposes a JSON API:

- API root:
  [desec.io/api/v1/](https://desec.io/api/v1/)
- Docs:
  [desec.readthedocs.io](https://desec.readthedocs.io/)

You'll use either the web UI or the API to manage records. The rest
of this guide gives the records as zone-file lines; type them into the
desec UI, or POST them via the API.

## Step 3 — point your registrar's NS at desec

In the registrar's control panel, find "Nameservers" or "DNS Settings"
for `example.com`. Replace whatever's there with:

```
ns1.desec.io.
ns2.desec.org.
```

Save and wait for propagation. Until the parent `.com.` zone publishes
the new NS RRset, queries will still go to the old servers; that
typically takes 30 minutes to a few hours.

Verify:

```
$ dig +trace example.com NS
;; … walks down to the .com servers …
example.com.    172800  IN  NS  ns1.desec.io.
example.com.    172800  IN  NS  ns2.desec.org.
```

## Step 4 — submit the DS record so DNSSEC actually works end-to-end

This is the step every first-time operator forgets. Putting NS records
at desec without a DS in the parent leaves you with **insecure
delegation** — desec is signing your zone, but no validator believes
the signatures because the chain from `.com.` to your zone is broken.

In desec's web UI: **"Domains" → click `example.com` → "DS records"**.
desec shows you one or more DS records like:

```
example.com. IN DS  12345 13 2 1234567890ABCDEF1234567890ABCDEF...
```

Copy this **into your registrar's control panel**, in the "DNSSEC"
section. The fields you'll be asked for:

| Field          | Maps to              |
| -------------- | -------------------- |
| Key Tag        | `12345` (first num)  |
| Algorithm      | `13` (ECDSAP256SHA256) |
| Digest Type    | `2` (SHA-256)        |
| Digest         | the long hex string  |

Save. The registrar pushes the DS to the `.com.` registry; once it's
live (15 minutes to a few hours), the chain is complete.

Verify:

```
$ dig +dnssec +trace example.com SOA
;; … look for "ad" flag in the final answer (Authenticated Data) …
$ dig +short DS example.com @8.8.8.8
12345 13 2 1234567890ABCDEF...
```

Or use the
[Verisign DNSSEC Debugger](https://dnssec-analyzer.verisignlabs.com/example.com)
or [DNSViz](https://dnsviz.net/d/example.com/dnssec/) — both render
the chain visually and tell you exactly what's broken if anything is.

You're now running a DNSSEC-secured zone for free.

## Step 5 — add email-security records at the apex

These all go in the `example.com.` zone (managed at desec). They make
the difference between "anybody can spoof your domain in email" and
"a properly configured receiver will reject the spoof."

### MX — where mail for `@example.com` is delivered

```dns
example.com.    IN  MX  10 mail.example.com.
mail.example.com. IN  A     203.0.113.10
mail.example.com. IN  AAAA  2001:db8::10
```

If you're using a third-party email provider (Fastmail, Migadu, MXroute,
G-Suite, Microsoft 365…), use *their* MX records — they'll give you
the values.

### SPF — which servers are allowed to send mail "From: @example.com"

A single TXT record at the zone apex:

```dns
example.com.    IN  TXT  "v=spf1 mx -all"
```

Variants:

| Need                                          | Record                                                |
| --------------------------------------------- | ----------------------------------------------------- |
| Only your MX hosts send                       | `"v=spf1 mx -all"`                                    |
| Your MX hosts + a specific IP block           | `"v=spf1 mx ip4:203.0.113.0/24 -all"`                 |
| Plus a third-party (e.g. SendGrid)            | `"v=spf1 mx include:sendgrid.net -all"`               |
| Migadu user                                   | `"v=spf1 include:spf.migadu.com -all"`                |
| Fastmail user                                 | `"v=spf1 include:spf.messagingengine.com -all"`       |
| Domain doesn't send mail at all               | `"v=spf1 -all"`                                       |

`-all` is hard-fail (recommended for production). `~all` is soft-fail
(rolling out). RFC 7208.

### DKIM — public key for outbound mail signatures

DKIM uses **selectors** so you can rotate keys. Your mail server
generates a keypair; the public part goes in DNS at
`<selector>._domainkey.example.com`:

```dns
s1._domainkey.example.com.  IN  TXT  ( "v=DKIM1; k=rsa; "
                                       "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB"
                                       "CgKCAQEAvF…" )
```

The selector name (`s1`) is up to you; many providers use a date-based
selector like `2024Q1`. The `p=` value comes from your mail server's
DKIM configuration. RFC 6376.

If you use a hosted email provider, they hand you exact records to
paste in.

### DMARC — what to do with mail that fails SPF or DKIM

```dns
_dmarc.example.com.  IN  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; aspf=r; adkim=r;"
```

Fields:

- `p=` — policy: `none` (just monitor), `quarantine` (spam folder),
  `reject` (drop). Start with `none`, move up.
- `rua=` — aggregate reports go here daily.
- `aspf=`, `adkim=` — alignment mode: `r` relaxed, `s` strict.

A typical rollout takes weeks — start at `p=none`, watch the reports
that arrive at `rua`, fix legitimate sources that fail alignment, then
escalate to `quarantine` and finally `reject`. RFC 7489.

### MTA-STS — force STARTTLS for incoming mail

MTA-STS is two records: a TXT pointing to a policy file, and the
policy file served over HTTPS.

```dns
_mta-sts.example.com.  IN  TXT  "v=STSv1; id=20240128T120000Z;"
mta-sts.example.com.   IN  A    203.0.113.20      ; webserver hosting the policy
```

The `id` is a string that changes whenever the policy file changes —
common pattern is a UTC timestamp.

The policy file lives at:

```
https://mta-sts.example.com/.well-known/mta-sts.txt
```

with content like:

```
version: STSv1
mode: enforce
mx: mail.example.com
max_age: 86400
```

`mode: enforce` is the production mode; sending MTAs will refuse to
deliver if STARTTLS can't be negotiated to one of the listed MX hosts.
RFC 8461.

### TLS-RPT — receive reports about TLS-delivery failures

```dns
_smtp._tls.example.com.  IN  TXT  "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"
```

Once a day, sending MTAs will email you a JSON summary of any TLS
failures they had delivering to you. Useful when troubleshooting
MTA-STS rollouts. RFC 8460.

### DANE / TLSA — cryptographic pinning for SMTP TLS

DANE is the strongest form of TLS authentication for email — sending
MTAs validate your TLS cert against a hash you publish in DNS.
**DNSSEC is mandatory for DANE to work**: without it, MTAs ignore the
TLSA record. Since you have DNSSEC via desec, you can use it.

```dns
_25._tcp.mail.example.com.  IN  TLSA  3 1 1 ABCDEF1234567890...
```

The four fields:

| Field           | Common value | Meaning                                              |
| --------------- | ------------ | ---------------------------------------------------- |
| Usage           | `3`          | DANE-EE — match against your end-entity cert         |
| Selector        | `1`          | SubjectPublicKeyInfo (preferred over full cert)      |
| Matching type   | `1`          | SHA-256                                              |
| Certificate     | hex digest   | SHA-256 of your mail server's public-key bytes       |

Generating the digest from a PEM cert:

```
$ openssl x509 -in mail.example.com.crt -pubkey -noout |
  openssl pkey -pubin -outform DER |
  sha256sum
```

The digest is what goes after `3 1 1 `. RFC 7672.

When you rotate your mail-server cert, publish the new TLSA record
**alongside** the old one a few days before swapping the cert; remove
the old TLSA only after the cutover. Otherwise sending MTAs that
cached the old TLSA will reject deliveries during the window.

### Optional: DKIM-Reporting, BIMI, OPENPGPKEY, SMIMEA

- **BIMI** ([bimigroup.org](https://bimigroup.org/)) — display your
  brand logo in receivers' inboxes. Requires DMARC at `enforce` and a
  Verified Mark Certificate.
- **OPENPGPKEY** (RFC 7929) — publish PGP public keys in DNSSEC-signed
  DNS for automatic discovery.
- **SMIMEA** (RFC 8162) — same idea for S/MIME certificates.

Both OPENPGPKEY and SMIMEA require DNSSEC, so you can run them on the
desec side. dns2ts doesn't yet have structured types for these; the
generic `UnknownPacketType` works as a fallback if you ever serve them
from your own subdomain.

## Step 6 — delegate a subdomain to your own dns2ts server

Now the part where your own infrastructure comes into play. You want
`lab.example.com.` (or some subset) to be served by a dns2ts server
you run.

In the desec UI for `example.com.`, add NS records:

```dns
lab.example.com.  IN  NS  ns1.example.com.
lab.example.com.  IN  NS  ns2.example.com.
ns1.example.com.  IN  A   198.51.100.7
ns2.example.com.  IN  A   198.51.100.8
```

The two A records (your nameservers' addresses) live at the desec
parent zone — there's no chicken-and-egg here because the names are
under `example.com.` itself, not under `lab.`. If you used in-bailiwick
names like `ns1.lab.example.com.`, you'd need glue inside the
delegation; the [subdomain delegation guide](subdomain-delegation.md)
covers that case.

Now spin up dns2ts as the authoritative server for `lab.example.com.`
(see [DNS servers](dns-servers.md)). The basic shape:

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

    response.answers = zone.records.filter((r) =>
      r.name.toLowerCase() === q.name.toLowerCase() &&
      (r.packetType.type === q.type || q.type === PacketTypes.ANY));

    if (response.answers.length === 0) response.header.rcode = 3; // NXDOMAIN
    send(response);
  },
});
await server.listen({udp: 53, tcp: 53});
```

Zone file (`lab.example.com.zone`):

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

Verify the delegation:

```
$ dig +trace www.lab.example.com
$ dig @ns1.example.com lab.example.com SOA
$ dig +dnssec lab.example.com NS @8.8.8.8
;; → desec's NS records for lab + RRSIG (signed parent),
;;   then resolver follows to your server (unsigned answers)
```

## DNSSEC at the cut — what "insecure delegation" means

When you delegate `lab.example.com.` from desec, the desec parent zone
publishes:

- The NS RRset (signed)
- The glue A/AAAA records (signed)
- **No DS record** for `lab.`, because your dns2ts server doesn't sign

A DNSSEC validator walking the chain reaches the cut, sees signed NS
records, looks for a DS, finds none, and verifies via desec's NSEC3
records that the absence of DS is **legitimate** (not a downgrade
attack). It concludes "this delegation is intentionally insecure"
and accepts unsigned answers from your dns2ts server.

This is the standard pattern for mixed-signing setups. Some validators
display this as the `ad` flag being absent for queries under `lab.`,
which is correct — those answers aren't authenticated.

What this means in practice:

- `example.com.` and everything *not* under `lab.` is fully signed and
  validates with `ad`.
- `lab.example.com.` and everything under it doesn't validate (no
  DNSSEC), but answers are still served correctly.
- Protocols that *require* DNSSEC (DANE/TLSA on a sub-mail-server,
  OPENPGPKEY) won't work under `lab.` — keep those records at the
  desec-managed apex.

## When dns2ts gains DNSSEC signing later

Once dns2ts can sign zones (tracked on the [roadmap](../README.md)),
you'll:

1. Generate KSK + ZSK keys for `lab.example.com.`
2. Sign the zone with dns2ts
3. Compute the DS record for the KSK
4. **Add the DS to the desec parent zone** for `lab.example.com.`
5. The chain now extends from `.com.` → desec → your dns2ts, all
   validating end to end

That submission is one TXT-equivalent change at desec; nothing else
needs to change at the registrar.

## Verification cheatsheet

After every change, run these:

| Command                                                            | Tells you                                                  |
| ------------------------------------------------------------------ | ---------------------------------------------------------- |
| `dig +dnssec +short example.com SOA`                               | Returns SOA + RRSIG → desec is signing                     |
| `dig +short DS example.com @a.gtld-servers.net.`                   | DS in parent (the .com side) → registrar pushed it         |
| `dig +trace +dnssec example.com`                                   | Walks the full chain from root                             |
| `dig +short MX example.com`                                        | MX records returned                                        |
| `dig +short TXT example.com`                                       | SPF (and any other apex TXT) returned                      |
| `dig +short TXT _dmarc.example.com`                                | DMARC policy returned                                      |
| `dig +short TXT s1._domainkey.example.com`                         | DKIM public key returned                                   |
| `dig +short TXT _mta-sts.example.com`                              | MTA-STS pointer record                                     |
| `curl -s https://mta-sts.example.com/.well-known/mta-sts.txt`      | MTA-STS policy file                                        |
| `dig +short TLSA _25._tcp.mail.example.com`                        | DANE/TLSA digest                                           |
| `dig +short NS lab.example.com`                                    | Delegation NS records pointing at your server              |
| `dig @ns1.example.com lab.example.com SOA`                         | Direct talk to your dns2ts server                          |
| `dig +trace www.lab.example.com`                                   | End-to-end resolution through the delegation               |

Online tools that visualize the whole chain at once:

- DNSViz: [dnsviz.net/d/example.com/dnssec/](https://dnsviz.net/d/example.com/dnssec/)
- Verisign DNSSEC Analyzer:
  [dnssec-analyzer.verisignlabs.com/example.com](https://dnssec-analyzer.verisignlabs.com/example.com)
- Mail-tester for SPF/DKIM/DMARC:
  [mail-tester.com](https://www.mail-tester.com/)
- MTA-STS validator: [aykevl.nl/apps/mta-sts](https://aykevl.nl/apps/mta-sts/)
- DANE checker: [dane.sys4.de](https://dane.sys4.de/)

## Common pitfalls

- **DS not submitted at registrar** — desec is signing but the parent
  doesn't know it. Validators see "no DS for delegated zone" and treat
  the whole zone as insecure. Symptom: `dig +short DS example.com
  @a.gtld-servers.net.` returns nothing. Fix: paste the DS into the
  registrar's DNSSEC section.
- **Wrong DS digest** — re-check that you copied the digest exactly
  from desec's UI (no truncation, no extra spaces). Some registrars
  parse the full DS record line; some want fields separately. The
  field order is always: keytag, algorithm, digest-type, digest.
- **MTA-STS HTTPS endpoint missing** — the TXT record points at a URL
  that doesn't resolve or doesn't serve `mta-sts.txt`. Sending MTAs
  ignore the policy. Verify with `curl`.
- **DKIM record split incorrectly** — DKIM public keys are long,
  exceeding the 255-char per-string TXT limit. Multi-string TXTs
  concatenate fine on the wire, but make sure your editor / API
  client doesn't insert literal whitespace into the value (only into
  the spaces *between* the quoted strings). Use `dig +short TXT
  s1._domainkey.example.com` to read back what's actually published.
- **DANE/TLSA without DNSSEC** — silently ignored. If you're seeing
  this, your DNSSEC chain is broken at some level — chase it down with
  DNSViz.
- **NS RRset mismatch between desec and your child server** — your
  zone's apex `lab.example.com NS` records must match what desec
  publishes for `lab.example.com NS`. Add both `ns1` and `ns2` in
  both places.
- **SPF too long / 10-lookup limit** — SPF allows ≤10 DNS lookups
  during evaluation; nested includes count. If you hit the limit, mail
  fails. Tools: [spf-record.com](https://www.spf-record.com/) or
  [dmarcian.com/spf-survey](https://dmarcian.com/spf-survey/).
- **TTL surprise on big changes** — if you lower MX or DS TTL **after**
  publishing the new value, caches still hold the old one for the
  original TTL. Lower TTLs *first*, wait for them to drain, then make
  the change.

## A note on dynamic DNS (`dedyn.io`)

desec also offers `dedyn.io` — free dynamic DNS for IP-changing hosts
(home internet, Raspberry Pis, etc.). Each user gets a subdomain like
`yourname.dedyn.io` that they can update via API. Independent from the
"bring your own domain" path described here, but it's a nice option
for the IP-bound parts of your infrastructure (the dns2ts server
itself, if you're hosting at home).

## References

### desec.io

- desec home: [desec.io](https://desec.io/)
- API docs:
  [desec.readthedocs.io](https://desec.readthedocs.io/)
- Status / outages: [status.desec.io](https://status.desec.io/)

### Email-security RFCs

- **SPF**: [RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208)
- **DKIM**: [RFC 6376](https://datatracker.ietf.org/doc/html/rfc6376)
- **DMARC**: [RFC 7489](https://datatracker.ietf.org/doc/html/rfc7489)
  (and [RFC 9091](https://datatracker.ietf.org/doc/html/rfc9091) on alignment)
- **MTA-STS**: [RFC 8461](https://datatracker.ietf.org/doc/html/rfc8461)
- **TLS-RPT**: [RFC 8460](https://datatracker.ietf.org/doc/html/rfc8460)
- **DANE for SMTP**: [RFC 7672](https://datatracker.ietf.org/doc/html/rfc7672)
- **OPENPGPKEY**: [RFC 7929](https://datatracker.ietf.org/doc/html/rfc7929)
- **SMIMEA**: [RFC 8162](https://datatracker.ietf.org/doc/html/rfc8162)
- **BIMI**:
  [bimigroup.org](https://bimigroup.org/) (work-in-progress at IETF)

### DNSSEC RFCs

- [RFC 4033](https://datatracker.ietf.org/doc/html/rfc4033) — DNSSEC
  introduction and requirements
- [RFC 4034](https://datatracker.ietf.org/doc/html/rfc4034) — DNSSEC
  resource records (DNSKEY, DS, RRSIG, NSEC)
- [RFC 4035](https://datatracker.ietf.org/doc/html/rfc4035) — DNSSEC
  protocol modifications, including handling of insecure delegations
- [RFC 5155](https://datatracker.ietf.org/doc/html/rfc5155) — NSEC3
  (zone-walking-resistant denial of existence)
- [RFC 7344](https://datatracker.ietf.org/doc/html/rfc7344) — automating
  DS record submission via CDS/CDNSKEY (where supported)

### DNSSEC validation tools

- DNSViz: [dnsviz.net](https://dnsviz.net/)
- Verisign DNSSEC Analyzer:
  [dnssec-analyzer.verisignlabs.com](https://dnssec-analyzer.verisignlabs.com/)
- ICANN DNSSEC validator info:
  [icann.org/resources/pages/dnssec-en](https://www.icann.org/resources/pages/dnssec-en)

### Email-security validators

- mail-tester: [mail-tester.com](https://www.mail-tester.com/)
- DMARC analyzer: [dmarcian.com](https://dmarcian.com/)
- MTA-STS validator: [aykevl.nl/apps/mta-sts](https://aykevl.nl/apps/mta-sts/)
- DANE checker: [dane.sys4.de](https://dane.sys4.de/)
- SPF tools: [spf-record.com](https://www.spf-record.com/),
  [easydmarc.com/tools/spf-record-lookup](https://easydmarc.com/tools/spf-record-lookup)

## Related

- [Subdomain delegation](subdomain-delegation.md) — the general
  mechanism this guide specializes; covers in-bailiwick NS, glue,
  multi-NS replication.
- [DNS servers](dns-servers.md) — running the dns2ts authoritative
  server for the delegated subdomain.
- [Zone files](zone-files.md) — how the `Zone` is loaded.
- [TSIG](tsig.md) — if you eventually run a primary/secondary pair
  with [AXFR](axfr.md)/[IXFR](ixfr.md)/[NOTIFY](notify.md), authenticate
  the channel with TSIG.
- [Reverse proxy](reverse-proxy.md) — TLS termination and rate limiting
  in front of your auth server, if it serves DoT/DoH.
- [Becoming a registrar](becoming-a-registrar.md) — if you want to
  *sell* domains rather than just secure your own.