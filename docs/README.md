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