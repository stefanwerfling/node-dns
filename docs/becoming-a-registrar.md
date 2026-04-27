# Becoming a domain registrar — what's actually involved

A **registrar** is the company end users buy domains from — Namecheap,
Cloudflare Registrar, GoDaddy, OVH, INWX. Different role from a
**registry** (which operates the TLD itself — see
[becoming-a-tld](becoming-a-tld.md)). The registry sells slots in their
zone wholesale; the registrar sells those slots retail to the public,
handles billing, customer support, and the EPP-side glue with each
registry.

Most "I want to start a domain business" goals end up here, not at the
registry tier — registrars are an order of magnitude cheaper and faster
to launch than a new TLD. Even so, an ICANN-accredited registrar is a
real regulated business with serious compliance overhead. This guide
covers the paths that actually exist, what each costs, and which one
probably fits.

## TL;DR

| What you want                           | Up-front cost           | Annual            | Time         |
| --------------------------------------- | ----------------------- | ----------------- | ------------ |
| **ICANN-accredited gTLD registrar**     | ~$3,500 + $70k working capital + insurance | $4,000 ICANN + per-tx | 6-12 months  |
| **ccTLD-only registrar** (e.g. `.de`)   | Per-registry agreement  | Per-registry      | 1-3 months   |
| **Reseller** of an accredited registrar | $0 - few hundred        | Per-tx margin     | hours        |
| **White-label storefront** on a wholesale API | Few hundred       | Per-tx margin     | days         |

For most launches, **start as a reseller**. You can run a real domain
business without ICANN accreditation, validate the market, then upgrade
to direct accreditation if volume justifies the overhead.

## The three real paths

### 1. ICANN-accredited gTLD registrar — the full path

You sign the **Registrar Accreditation Agreement (RAA)** with ICANN,
get an accreditation number, and from then on can talk directly to
every gTLD registry (`.com`, `.org`, `.shop`, `.xyz`, etc.) once you
have separate per-registry agreements with each.

#### What ICANN demands

- **Application + accreditation fee**: ~$3,500 one-time application,
  $4,000/year ongoing.
- **Variable per-transaction fees**: $0.18 per gTLD registration goes to
  ICANN.
- **Insurance**: Commercial General Liability of at least $500,000 per
  occurrence; Errors & Omissions / Professional Liability of at least
  $200,000.
- **Working capital**: ICANN currently expects you to demonstrate
  ~$70,000 in working capital (verified via bank statement, letter of
  credit, or audited financials).
- **Compliance with the 2013 RAA**: registrant data validation, abuse
  contact, escrow, transfer rules, WDRP / ERRP notices, etc.

ICANN's registrar pages:

- Application info:
  [icann.org/resources/pages/registrar-applications-2012-02-25-en](https://www.icann.org/resources/pages/registrar-applications-2012-02-25-en)
- Current 2013 RAA + specifications:
  [icann.org/resources/pages/approved-with-specs-2013-09-17-en](https://www.icann.org/resources/pages/approved-with-specs-2013-09-17-en)
- List of accredited registrars (~2,300 globally, mostly inactive):
  [icann.org/registrar-reports/accredited-list.html](https://www.icann.org/registrar-reports/accredited-list.html)

#### What every gTLD registry demands

Each registry-registrar agreement is separate. Common requirements:

- **Registry deposit / monthly minimum**: many registries want a
  prepaid deposit (e.g. Verisign for `.com` typically expects mid-five-
  figures upfront) and/or a monthly minimum spend.
- **EPP integration certification**: you must pass each registry's
  Operational Test Environment (OTE) before they let you write to
  production. Multi-week effort per registry.
- **Trademark Clearinghouse integration** during sunrise periods.

So getting `.com` selling alone realistically needs $50k-$100k tied up
in registry deposits + integration work, on top of the ICANN side.

#### The Registrar Accreditation Agreement obligations

Highlights of what you sign up for in the
[2013 RAA](https://www.icann.org/resources/pages/approved-with-specs-2013-09-17-en):

- **Validate registrant contact info** (email at minimum) within 15
  days of registration. Suspend names whose contacts can't be
  validated.
- **Maintain a 24/7 abuse contact** and respond to abuse reports.
- **Escrow registration data** with an ICANN-approved escrow agent
  ([Iron Mountain](https://www.ironmountain.com/services/data-management/data-escrow),
  [NCC Group](https://www.nccgroup.com/), …).
- **Comply with the Inter-Registrar Transfer Policy (IRTP)**:
  [icann.org/resources/pages/transfer-policy-2017-02-25-en](https://www.icann.org/resources/pages/transfer-policy-2017-02-25-en).
- **Whois Data Reminder Policy (WDRP)**: send registrants annual
  contact-data reminders.
- **Expired Registration Recovery Policy (ERRP)**: specific timing for
  notifying registrants of upcoming expiration and grace-period
  redemption.
- **Uniform Domain-Name Dispute-Resolution Policy (UDRP)** and **Uniform
  Rapid Suspension (URS)**: if a complainant proves bad-faith
  registration of a trademark-protected name, you cooperate with the
  forced transfer or suspension.
- **Data protection / GDPR**: register data display restrictions
  (everything you used to see in WHOIS is now redacted by default).

Realistic timeline: ~6-12 months from "decide to do this" to "live
selling `.com`." Smaller TLDs can come online faster; major ones take
longer because of OTE certification queues.

### 2. ccTLD-only registrar

If you only sell country-code domains (`.de`, `.uk`, `.fr`, `.jp`,
`.ch`, …), you skip ICANN entirely. Each ccTLD is governed by its own
country registry — they have their own accreditation procedures, their
own technical APIs (some use EPP, some have proprietary protocols),
their own contractual terms.

Examples:

- **`.de`** — DENIC. Membership requires being a German legal entity
  and paying a yearly fee.
  [denic.de/en/become-a-member](https://www.denic.de/en/become-a-member/)
- **`.uk`** — Nominet, with their own
  [registrar agreement](https://www.nominet.uk/become-a-registrar/).
- **`.eu`** — EURid, accredited registrars can bundle this.
  [eurid.eu](https://eurid.eu/en/register-eu-domains/become-a-eu-registrar/)
- **`.fr`** — AFNIC.
  [afnic.fr](https://www.afnic.fr/en/become-a-registrar/)
- **`.ch` / `.li`** — SWITCH for `.ch`,
  [nic.ch](https://www.nic.ch/en/registrar/).
- **`.jp`** — JPRS. Japan-only operations.

A ccTLD-focused launch is often the right move for a regional
registrar — much smaller compliance overhead than ICANN, and you can
focus on a market segment that demands local presence and language.

### 3. Reseller — the path everyone underestimates

You don't sign anything with ICANN. You partner with an
ICANN-accredited registrar (the **upstream**) who exposes a wholesale
API. You take orders from end users, your code calls the upstream's
API to register the domain, and the customer sees your brand on the
storefront.

Major wholesale registrar APIs:

- **OpenSRS** (Tucows) — one of the original wholesalers:
  [opensrs.com](https://opensrs.com/)
- **eNom** (also Tucows) — separate API:
  [enom.com](https://www.enom.com/) /
  [api.enom.com](https://api.enom.com/)
- **ResellerClub** (Newfold Digital):
  [resellerclub.com](https://www.resellerclub.com/)
- **Namecheap reseller**:
  [namecheap.com/resellers](https://www.namecheap.com/resellers/)
- **GoDaddy reseller** (now Domains by Proxy etc.):
  [godaddy.com/reseller](https://www.godaddy.com/reseller/)

Pros:

- Up-front cost is essentially zero. Sign up, get API keys, start
  selling.
- All the compliance/escrow/insurance/RAA burden is on the upstream.
- Your margin is the difference between wholesale and retail; for
  `.com` that's typically a few dollars per registration.

Cons:

- You're tied to the upstream's pricing, feature set, and reliability.
- Margins are thin without volume.
- You don't own the customer relationship at the deepest level — if
  the upstream goes down or kicks you off, you have a transfer
  problem.

This is how most "small registrar startups" actually launch. Many run
this way for years; some never bother upgrading to direct
accreditation because the volume doesn't justify it.

## Where dns2ts fits

A registrar's core technology is **EPP, billing, and a storefront** —
none of which is DNS. Your typical registrar stack:

- Storefront / customer portal (Web app)
- Billing / payment processing (Stripe, etc.)
- EPP client per registry you talk to (RFC 5730-5734)
- WHOIS / RDAP server for the names you manage
- Escrow integration
- Customer support tooling

But: registrars almost always offer **DNS hosting** as a value-add.
"Buy a domain, point it at our nameservers, manage records via our
control panel, free." This is where dns2ts comes in:

- The authoritative server that holds every customer's zone — see
  [DNS servers](dns-servers.md).
- Customer record edits in your control panel translate to
  [DNS UPDATE](update.md) calls into the auth servers (TSIG-signed,
  see [TSIG](tsig.md)).
- Multi-region anycast nameservers replicating with
  [AXFR](axfr.md)/[IXFR](ixfr.md) and triggered by
  [NOTIFY](notify.md).
- TLS termination and rate limiting at the edge — see
  [reverse proxy](reverse-proxy.md).

A small registrar offering DNS hosting for their customers can run
exactly that pattern with dns2ts as the auth-server piece. It's the
same architecture the [subdomain delegation guide](subdomain-delegation.md)
describes, scaled out per-customer.

dns2ts is **not** an EPP client/server, **not** a WHOIS/RDAP server,
**not** a billing system. Those are separate stacks you'll either
build, license, or pull from open-source registrar projects.

## Open-source registrar building blocks

There's no end-to-end open-source "registrar in a box," but you can
assemble one from existing pieces:

- **EPP libraries**:
  - [`net-epp` (Perl)](https://metacpan.org/pod/Net::EPP) — mature.
  - [`epp-client` (Ruby)](https://github.com/epp-rb/epp-client).
  - [`python-epp` and pyepp](https://github.com/CZ-NIC/pyfred) — CZ.NIC has a
    full registrar/registry stack in Python.
  - JS/TS: thinner ecosystem; you may end up writing the EPP layer
    yourself or shelling out to one of the libraries above.
- **WHOIS/RDAP server**: can ride on top of any web framework. RDAP
  is an HTTP+JSON API per
  [RFC 7480](https://datatracker.ietf.org/doc/html/rfc7480) /
  [RFC 9082](https://datatracker.ietf.org/doc/html/rfc9082) /
  [RFC 9083](https://datatracker.ietf.org/doc/html/rfc9083).
- **FRED** (CZ.NIC, full registry+registrar):
  [fred.nic.cz](https://fred.nic.cz/) — useful as a reference for a
  full implementation, even if you don't deploy it.
- **CoCCA**: [cocca.org.nz](https://cocca.org.nz/) — used by several
  smaller TLDs and registrars.

## Compliance, abuse, and the realities of running one

Once you're live, the operational/legal load is real:

- **Abuse handling**: phishing, malware, trademark complaints arrive.
  You have to respond on a clock per the RAA.
- **GDPR / data protection**: you're processing personal data (every
  registrant). Privacy policy, lawful basis, DPO if scale warrants.
- **Verification calls**: ICANN spot-checks your registrant
  validation; failures trigger compliance actions and ultimately
  accreditation suspension.
- **Transfer disputes**: customers transfer in/out and sometimes
  contest. You implement IRTP correctly or you get complaints.
- **Tax**: you sell across borders. VAT/GST and equivalent rules
  apply per jurisdiction.

The reseller path offloads most of these to the upstream — that's the
single biggest reason most small operators stay reseller for years.

## Realistic decision tree

Use this to pick the right tier:

| Situation                                                               | Best path                  |
| ----------------------------------------------------------------------- | -------------------------- |
| Want to start tomorrow, validate the market                             | Reseller                   |
| Need a regional/language-specific registrar with low overhead           | ccTLD-only direct          |
| Doing >5,000 registrations/year already as a reseller                   | Upgrade to ICANN-accredited |
| Want to operate at the scale of GoDaddy / Cloudflare                    | ICANN-accredited from day 1 |
| Building this as a feature inside a larger product (hosting, etc.)      | Reseller via OpenSRS/eNom  |
| Just want to register-and-park names for your own projects              | Don't be a registrar; buy them |

## Reference list

### ICANN

- ICANN home: [icann.org](https://www.icann.org/)
- Registrar applications:
  [icann.org/resources/pages/registrar-applications-2012-02-25-en](https://www.icann.org/resources/pages/registrar-applications-2012-02-25-en)
- 2013 RAA + specifications:
  [icann.org/resources/pages/approved-with-specs-2013-09-17-en](https://www.icann.org/resources/pages/approved-with-specs-2013-09-17-en)
- List of accredited registrars:
  [icann.org/registrar-reports/accredited-list.html](https://www.icann.org/registrar-reports/accredited-list.html)
- IRTP (transfer policy):
  [icann.org/resources/pages/transfer-policy-2017-02-25-en](https://www.icann.org/resources/pages/transfer-policy-2017-02-25-en)
- UDRP (dispute resolution):
  [icann.org/resources/pages/policy-2012-02-25-en](https://www.icann.org/resources/pages/policy-2012-02-25-en)
- URS (rapid suspension):
  [icann.org/resources/pages/urs](https://www.icann.org/resources/pages/urs-2014-01-09-en)
- Compliance (abuse, audits):
  [icann.org/compliance](https://www.icann.org/compliance)

### Major ccTLD registries

- DENIC (`.de`):
  [denic.de/en/become-a-member](https://www.denic.de/en/become-a-member/)
- Nominet (`.uk`):
  [nominet.uk/become-a-registrar](https://www.nominet.uk/become-a-registrar/)
- EURid (`.eu`):
  [eurid.eu](https://eurid.eu/en/register-eu-domains/become-a-eu-registrar/)
- AFNIC (`.fr`):
  [afnic.fr](https://www.afnic.fr/en/become-a-registrar/)
- SWITCH (`.ch`/`.li`):
  [nic.ch/en/registrar](https://www.nic.ch/en/registrar/)
- JPRS (`.jp`): [jprs.jp](https://jprs.jp/en/) (Japan-only)

### Wholesale registrar APIs (for resellers)

- OpenSRS: [opensrs.com](https://opensrs.com/)
- eNom: [enom.com](https://www.enom.com/) /
  [api.enom.com](https://api.enom.com/)
- ResellerClub: [resellerclub.com](https://www.resellerclub.com/)
- Namecheap reseller:
  [namecheap.com/resellers](https://www.namecheap.com/resellers/)
- GoDaddy reseller: [godaddy.com/reseller](https://www.godaddy.com/reseller/)

### EPP — protocol RFCs

- [RFC 5730](https://datatracker.ietf.org/doc/html/rfc5730) — EPP core
- [RFC 5731](https://datatracker.ietf.org/doc/html/rfc5731) — EPP
  domain mapping
- [RFC 5732](https://datatracker.ietf.org/doc/html/rfc5732) — EPP host
  mapping
- [RFC 5733](https://datatracker.ietf.org/doc/html/rfc5733) — EPP
  contact mapping
- [RFC 5734](https://datatracker.ietf.org/doc/html/rfc5734) — EPP over
  TCP

### RDAP — modern WHOIS replacement

- [RFC 7480](https://datatracker.ietf.org/doc/html/rfc7480) — RDAP
  HTTP usage
- [RFC 9082](https://datatracker.ietf.org/doc/html/rfc9082) — query
  format
- [RFC 9083](https://datatracker.ietf.org/doc/html/rfc9083) — JSON
  responses
- ICANN RDAP profile:
  [icann.org/rdap-2017-04-15-en](https://www.icann.org/resources/pages/rdap-2017-04-15-en)

### Open-source registrar/registry stacks

- FRED (CZ.NIC): [fred.nic.cz](https://fred.nic.cz/)
- CoCCA: [cocca.org.nz](https://cocca.org.nz/)
- pyfred / pyepp:
  [github.com/CZ-NIC/pyfred](https://github.com/CZ-NIC/pyfred)

### Data escrow agents

- Iron Mountain:
  [ironmountain.com/services/data-management/data-escrow](https://www.ironmountain.com/services/data-management/data-escrow)
- NCC Group: [nccgroup.com](https://www.nccgroup.com/)
- EBRP: [ebrp.net](https://www.ebrp.net/)

## Honest summary

If your goal is "build a domain-name business":

- **Don't start with ICANN accreditation.** Become a reseller via
  OpenSRS/eNom/ResellerClub first. Days to launch, no compliance
  overhead, real revenue from day one.
- **Upgrade to direct accreditation only when volume justifies it.**
  ICANN's $4k/year fee, the $0.18 per-transaction fee, the insurance
  requirements, and the working-capital lock-up are real costs that
  only pay back at scale.
- **For region-specific markets, go ccTLD-direct.** A small
  Germany-focused registrar can be DENIC-direct without ever touching
  ICANN.

The technology piece is the easy part. dns2ts handles the DNS-hosting
value-add a registrar typically offers, but the rest of the stack —
EPP, WHOIS/RDAP, billing, abuse handling, transfer disputes, GDPR —
is its own world.

## Related

- [Becoming a TLD](becoming-a-tld.md) — the **registry** path (operating
  a TLD itself, not selling names under it).
- [Subdomain delegation](subdomain-delegation.md) — how to delegate a
  subdomain to your own dns2ts server, the building block under
  registrar-offered DNS hosting.
- [DNS servers](dns-servers.md) — running the auth servers that back
  customer DNS hosting.
- [DNS UPDATE](update.md) — wire customer record edits into the auth
  servers.
- [AXFR](axfr.md) / [IXFR](ixfr.md) / [NOTIFY](notify.md) — primary →
  secondary replication across anycast nodes.
- [TSIG](tsig.md) — authenticate the EPP→DNS pipeline and the
  primary↔secondary channels.
- [Reverse proxy](reverse-proxy.md) — TLS termination, rate limiting,
  IP transparency for the auth servers.