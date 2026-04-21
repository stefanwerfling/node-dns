# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**dns2ts** — a pure TypeScript DNS server and client library with zero production dependencies. Implements DNS over UDP, TCP, TLS, and HTTPS (DoH).

## Build & Development Commands

```bash
npm install              # Install dev dependencies
npx tsc                  # Compile TypeScript (src/ -> dist/)
npm test                 # Compile + run all tests (tsc && node dist/Test)
npm run lint             # ESLint check
npm run fix              # ESLint auto-fix
```

Example servers (run after compiling):
```bash
npm run example-server-udp    # Start UDP DNS server
npm run example-server-tcp    # Start TCP DNS server
```

## Code Style (enforced by ESLint)

- 4-space indentation, single quotes, semicolons required
- Explicit function return types (`@typescript-eslint/explicit-function-return-type`)
- Explicit member accessibility on classes (`@typescript-eslint/explicit-member-accessibility`)
- Arrow functions preferred (`prefer-arrow/prefer-arrow-functions`)
- Import extensions required — always use `.js` suffix in imports (NodeNext module resolution)
- Object shorthand disabled — use `{ key: key }` not `{ key }`
- No implicit coercion (`no-implicit-coercion`)
- No parameter reassignment (`no-param-reassign`)
- Class bodies padded with blank lines (`padded-blocks: classes: always`)
- No trailing newline at end of file (`eol-last: never`)

## Architecture

### Module Layout (src/)

- **Lib/** — Low-level I/O: `BufferReader`/`BufferWriter` for bit-level DNS wire format parsing, `SocketReader` for TCP stream framing (accepts an optional `initialBuffer` so pre-consumed bytes can be fed in).
- **Packet/** — DNS packet model (RFC 1035): header, question, resource record encoding/decoding, domain name compression, class/type enums
- **Packet/Types/** — 22 record type implementations (A, AAAA, MX, NS, CNAME, PTR, SRV, SOA, TXT, SPF, CAA, EDNS with ECS, DNSKEY, DS, NAPTR, NSEC, NSEC3, RRSIG, SSHFP, TLSA, SVCB, HTTPS), each extending abstract `PacketType`. HTTPS is a thin subclass of SVCB — same RFC 9460 wire format, different type code. Unknown types are handled gracefully via `UnknownPacketType`.
- **Server/** — `UDPServer`, `TCPServer`, `DohServer` (individual protocol servers) and `DnsServer` (combined multi-protocol server). Shared config in `ServerOptions`. Two hook interfaces: `ServerPreRequest<TClient>` (per message, for all three transports) and `ServerPreConnection<TClient>` (per TCP connection).
- **Server/ProxyProtocol/** — PROXY protocol v1 (text) and v2 (binary) implementations. `ProxyProtocolV1`/`V2` implement `ServerPreRequest<dgram.RemoteInfo>` for UDP; `ProxyProtocolV1Tcp`/`V2Tcp` implement `ServerPreConnection<net.Socket>` and override `remoteAddress`/`remotePort` via `Object.defineProperty`. `ProxyProtocolTcpReader` is the shared incremental socket-reading helper.
- **Client/** — `UDPClient`, `TCPClient` (TCP + TLS), `DohClient` (http/https/h2), `GoogleClient` (Google JSON API). All expose a static `request()` method returning a `ClientRequest` resolver function.
- **DNS.ts** — High-level resolver that tries multiple nameservers in parallel, supports all protocol types.
- **Test/** — Test framework and test suite (49 tests covering packets, EDNS, record types, SVCB/HTTPS params, PROXY protocol parsers, servers, integration incl. TCP+PROXY end-to-end).
- **index.ts** — Barrel re-export of all public API

### Key Patterns

- **PacketTypeRegistry** is a singleton that maps DNS record type numbers to `PacketType` subclass instances. All 22 types are registered at first access.
- **Buffer operations** work at the bit level — `BufferReader`/`BufferWriter` use bit arrays (0/1 values) for flexible sub-byte field parsing (DNS header flags, etc.). When using `BufferWriter.writeBuffer()`, pass a `Buffer` (bytes→bits conversion) or another `BufferWriter` (bit array copy).
- **TCP framing** uses 2-byte length prefix per message, handled by `SocketReader`.
- **Servers** emit `request` events with parsed `Packet` objects and a send callback. `DnsServer` combines multiple protocol servers and forwards all events.
- **Pre-hooks** — `preRequest` (per-message) and `preConnection` (TCP-only, per-connection) are configured via `ServerOptions.udp|tcp|doh`. Both can return a `client` override that the server emits in place of the original. For TCP `preConnection`, the server passes the returned `initialBuffer` (any bytes read past the PROXY header) to `SocketReader.readStream` so DNS framing continues seamlessly. Responses always go back to the true transport peer; only the emitted client reference is swapped.
- **Clients** follow a factory pattern: `XClient.request(options)` returns an async resolver function `(name, type, cls, options?) => Promise<Packet>`.

### TypeScript / Module Config

- Target: ES2022, module: NodeNext (ESM)
- Strict mode enabled, declarations generated
- Source in `src/`, compiled output in `dist/`

### CI

- GitHub Actions: tests run on Node 22.x against `master` branch pushes/PRs
- Lint workflow runs on all pushes/PRs