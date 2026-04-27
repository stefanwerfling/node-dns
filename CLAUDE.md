# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**dns2ts** — a pure TypeScript DNS server and client library with zero production dependencies. Implements DNS over UDP, TCP, TLS (DoT, RFC 7858), and HTTPS (DoH, RFC 8484), client + server.

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
- **Packet/Types/** — 23 record type implementations (A, AAAA, MX, NS, CNAME, PTR, SRV, SOA, TXT, SPF, CAA, EDNS, DNSKEY, DS, NAPTR, NSEC, NSEC3, RRSIG, SSHFP, TLSA, SVCB, HTTPS, TSIG), each extending abstract `PacketType`. HTTPS is a thin subclass of SVCB — same RFC 9460 wire format, different type code. Unknown types are handled gracefully via `UnknownPacketType`. EDNS dispatches to per-option classes (`EdnsECS`, `EdnsCookie`, `EdnsPadding`, `EdnsNsid`, `EdnsKeepalive`, `EdnsExtendedError`) via the `EdnsOption` interface (each provides `encode(writer)` + static `decode`).
- **Packet/Types/EdnsCookie.ts** — DNS Cookies (RFC 7873) wire format plus RFC 9018-style server-cookie helpers: `generateClientCookie()`, `computeServerCookie(clientCookie, clientIp, secret, ts?)` returns 24 bytes (1B version + 3B reserved + 4B unix timestamp + 16B truncated HMAC-SHA256), `verifyServerCookie(...)` does a `crypto.timingSafeEqual` against a recomputed cookie and supports an optional `maxAgeSeconds` window.
- **Packet/Tsig.ts, Packet/TsigKey.ts** — TSIG signing + verification (RFC 8945). `TsigKey` holds the shared secret; `Tsig.sign(packet, key)` patches ARCOUNT, computes HMAC (built-in `crypto`) and appends the TSIG RR; `Tsig.verify(packet, receivedBytes, key)` relies on `PacketResource.byteStart` to slice the original wire bytes and does a constant-time MAC check plus fudge-window validation.
- **Server/** — `UDPServer`, `TCPServer`, `TLSServer` (DoT, RFC 7858), `DohServer` (individual protocol servers) and `DnsServer` (combined multi-protocol server). Shared config in `ServerOptions` (with `udp`/`tcp`/`tls`/`doh` blocks). `TLSServer` extends `TCPServer` by overriding two protected hooks (`_loadHooks` reads `options.tls.preRequest`/`preConnection`; `_createInternalServer` returns `tls.createServer(options.tls.options, listener)`); the rest of the framing/handler logic is inherited. Two hook interfaces: `ServerPreRequest<TClient>` (per message) and `ServerPreConnection<TClient>` (per TCP/TLS connection).
- **Server/ProxyProtocol/** — PROXY protocol v1 (text) and v2 (binary) implementations. `ProxyProtocolV1`/`V2` implement `ServerPreRequest<dgram.RemoteInfo>` for UDP; `ProxyProtocolV1Tcp`/`V2Tcp` implement `ServerPreConnection<net.Socket>` and override `remoteAddress`/`remotePort` via `Object.defineProperty`. `ProxyProtocolTcpReader` is the shared incremental socket-reading helper.
- **Client/** — `UDPClient`, `TCPClient` (TCP + TLS), `DohClient` (http/https/h2), `GoogleClient` (Google JSON API). All expose a static `request()` method returning a `ClientRequest` resolver function.
- **DNS.ts** — High-level resolver that tries multiple nameservers in parallel, supports all protocol types.
- **Test/** — Test framework and themed test modules (78 tests). `index.ts` is a thin barrel that imports the modules in order; tests live in `name.ts`, `packet.ts`, `edns.ts`, `recordTypes.ts`, `proxyProtocol.ts`, `tsig.ts`, `serverDoh.ts`, `serverIntegration.ts`, `serverTls.ts`. Shared fixtures (`response` buffer, HTTP `get` helper, bundled TLS cert/key, `dotQuery` helper) live in `helpers.ts`.
- **index.ts** — Barrel re-export of all public API

### Key Patterns

- **PacketTypeRegistry** is a singleton that maps DNS record type numbers to `PacketType` subclass instances. All 23 types are registered at first access.
- **PacketResource.byteStart** is populated by `PacketResource.decode` with the byte offset of the record in the source buffer. Required by TSIG verification to reconstruct the exact MAC input without re-serializing (which could produce different bytes if DNS compression differs).
- **Buffer operations** work at the bit level — `BufferReader`/`BufferWriter` use bit arrays (0/1 values) for flexible sub-byte field parsing (DNS header flags, etc.). When using `BufferWriter.writeBuffer()`, pass a `Buffer` (bytes→bits conversion) or another `BufferWriter` (bit array copy).
- **TCP framing** uses 2-byte length prefix per message, handled by `SocketReader`.
- **Servers** emit `request` events with parsed `Packet` objects and a send callback. `DnsServer` combines multiple protocol servers and forwards all events.
- **Pre-hooks** — `preRequest` (per-message) and `preConnection` (TCP/TLS-only, per-connection) are configured via `ServerOptions.udp|tcp|tls|doh`. Both can return a `client` override that the server emits in place of the original. For TCP/TLS `preConnection`, the server passes the returned `initialBuffer` (any bytes read past the PROXY header) to `SocketReader.readStream` so DNS framing continues seamlessly. Responses always go back to the true transport peer; only the emitted client reference is swapped.
- **Clients** follow a factory pattern: `XClient.request(options)` returns an async resolver function `(name, type, cls, options?) => Promise<Packet>`. `UDPClient` automatically retries via `TCPClient` when the response header has the TC (truncation) bit set (RFC 7766 §8); opt out via `tcpFallback: false`, override target with `tcpFallbackPort`.

### TypeScript / Module Config

- Target: ES2022, module: NodeNext (ESM)
- Strict mode enabled, declarations generated
- Source in `src/`, compiled output in `dist/`

### CI

- GitHub Actions: tests run on Node 22.x against `master` branch pushes/PRs
- Lint workflow runs on all pushes/PRs