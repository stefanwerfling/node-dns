# dns2ts documentation

In-depth guides per topic. The top-level [README](../README.md) has the
quick-start; this directory is for everything that doesn't fit a 30-line
example.

## Clients

- **[DNS clients](dns-clients.md)** — UDP, TCP, DoT, DoH, Google JSON, the
  combined `DNS` resolver, and the AXFR client. Includes UDP→TCP truncation
  fallback and TLS verification options.

## Servers

- **[DNS servers](dns-servers.md)** — `UDPServer`, `TCPServer`, `TLSServer`
  (DoT), `DohServer`, and the combined `DnsServer`. Covers the `request`
  event, the `send` callback (single packet or `Packet[]` for AXFR), pre-hooks,
  and lifecycle.

## Wire protocol

- **[Record types](record-types.md)** — every supported RR type with field
  reference, construction examples, and unsupported-type fallback.
- **[EDNS(0) options](edns.md)** — ECS, Cookies (incl. RFC 9018 server-cookie
  algorithm), Padding, NSID, TCP Keepalive, Extended DNS Errors.
- **[TSIG](tsig.md)** — transaction-signature signing/verification, fudge
  window, request-MAC chaining.

## Authoritative serving

- **[Subdomain delegation](subdomain-delegation.md)** — the DNS-structure
  primer: how NS records delegate authority, when glue is required,
  step-by-step recipe for moving `lab.example.com` onto your own dns2ts
  server, multi-NS replication, sub-delegation, verification, common
  pitfalls.
- **[Secure domain with desec.io](secure-domain-with-desec.md)** — a
  concrete recipe: free DNSSEC via desec.io as the parent service,
  every email-security record (SPF, DKIM, DMARC, MTA-STS, TLS-RPT,
  DANE/TLSA) configured at the apex, and a subdomain delegated onward
  to your own dns2ts server (insecure delegation today, full chain
  once dns2ts gains DNSSEC signing).
- **[Becoming a TLD](becoming-a-tld.md)** — honest walkthrough of the
  paths that actually exist (ICANN gTLD program, IETF special-use names,
  private/alternative roots), the costs and timelines, the ongoing
  registry-operator obligations (DNSSEC, EPP, RDAP, data escrow), where
  dns2ts fits, and realistic alternatives for most goals. Full link/RFC
  reference list.
- **[Becoming a registrar](becoming-a-registrar.md)** — the other half of
  the domain business: ICANN-accredited gTLD registrar (RAA terms,
  ~$70k working-capital + insurance), ccTLD-only direct (DENIC, Nominet,
  EURid, AFNIC, …), reseller via wholesale APIs (OpenSRS, eNom,
  ResellerClub) — the path most launches actually take. Where dns2ts
  fits as the DNS-hosting value-add layer.
- **[Zone files](zone-files.md)** — the RFC 1035 master file parser and the
  `Zone` class.
- **[AXFR](axfr.md)** — full zone transfer over TCP/TLS with the `Zone`
  helpers and the `AxfrClient`.
- **[IXFR](ixfr.md)** — incremental zone transfer (RFC 1995). `Zone.toIxfrPackets`
  picks the right shape (no-change / incremental / AXFR fallback) given
  an optional `ZoneChangeSet[]` history; `IxfrClient` classifies the
  response into a discriminated union.
- **[NOTIFY](notify.md)** — RFC 1996 zone-change notification: primary
  pushes "your zone changed" to secondaries via `NotifyClient`, secondary
  dispatches on `request.header.opcode === PacketOpcode.NOTIFY`.
- **[DNS UPDATE](update.md)** — RFC 2136 dynamic updates with
  `UpdateBuilder`, `UpdateClient`, `Update.applyToZone`. Five
  prerequisite forms, four update forms, RCODE-driven error handling.

## Deployment

- **[PROXY protocol](proxy-protocol.md)** — v1/v2 hooks for UDP datagrams
  and TCP connections.
- **[Reverse proxy](reverse-proxy.md)** — putting nginx, HAProxy, or Envoy in
  front of a dns2ts server. TLS termination, TLS passthrough, PROXY-protocol
  IP transparency, and troubleshooting.
- **[Security hardening](security-hardening.md)** — 0x20 query-name case
  randomization (`Random0x20`, opt-in via `use0x20: true` on clients) and
  bailiwick filtering (`Bailiwick.contains`, `Bailiwick.filter`) against
  off-path spoofing and cache-poisoning attacks.
- **[DNSSEC validation](dnssec.md)** — stateless RFC 4034/4035 verifier:
  `Dnssec.verifyRrsig`, `Dnssec.verifyDs`, `Dnssec.computeKeyTag`,
  `Dnssec.computeDsDigest`. Algorithms 8 (RSA/SHA-256), 10 (RSA/SHA-512),
  13 (ECDSA P-256), 14 (ECDSA P-384), 15 (Ed25519). DS digest types
  1/2/4. Chain-of-trust walking is the caller's responsibility.