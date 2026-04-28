
![NPM version](https://img.shields.io/npm/v/dns2.svg?style=flat)
[![Node.js CI](https://github.com/song940/node-dns/actions/workflows/node.js.yml/badge.svg)](https://github.com/song940/node-dns/actions/workflows/node.js.yml)

# dns2ts

<p align="center">
<img src="/doc/images/logo.png" width="300px" style="border-radius: 15px;transition: transform .2s;object-fit: cover;">
<br><br>
</p>

<hr>

### Pure TypeScript (Fork)

Fully rewritten from JavaScript to TypeScript — no JS source files remain.

- Real types from TypeScript source, not just definition files (*.d.ts)
- Zero production dependencies
- ESM module format (NodeNext)
- Transports: UDP, TCP, TLS (DoT, RFC 7858) and HTTPS (DoH, RFC 8484), client + server
- 24 record types: A, AAAA, MX, NS, CNAME, DNAME, PTR, SRV, SOA, TXT, SPF, CAA, EDNS, DNSKEY, DS, NAPTR, NSEC, NSEC3, RRSIG, SSHFP, TLSA, SVCB, HTTPS (RFC 9460), TSIG
- EDNS(0) options: ECS (RFC 7871), Cookies (RFC 7873 + RFC 9018 server-cookie algorithm), Padding (RFC 7830), NSID (RFC 5001), TCP Keepalive (RFC 7828), Extended DNS Errors (RFC 8914)
- TSIG transaction signing (RFC 8945) — HMAC-based request/response authentication with hmac-md5/sha1/sha224/sha256/sha384/sha512
- PROXY protocol v1 and v2 support (UDP per-datagram, TCP per-connection) for transparent load-balancer deployments
- RFC 1035 master file ("zone file") parser — `$ORIGIN`, `$TTL`, `@`, multi-line records via parens, quoted strings; RDATA for A, AAAA, NS, CNAME, DNAME, PTR, MX, TXT, SOA, SRV, CAA, DNSKEY, DS, SSHFP, TLSA, NAPTR, NSEC, NSEC3, RRSIG, SVCB, HTTPS (RFC 3597 generic `TYPEnnn` mnemonic, base32hex for NSEC3, RFC 9460 SVCB presentation form)
- DNSSEC validation **and signing** (RFC 4034 / 4035) — stateless `Dnssec.verifyRrsig`, `Dnssec.signRrset`, `Dnssec.publicKeyToDnskey`, `Dnssec.computeKeyTag`, `Dnssec.computeDsDigest`, `Dnssec.verifyDs`. Algorithms 8 (RSA/SHA-256), 10 (RSA/SHA-512), 13 (ECDSA P-256), 14 (ECDSA P-384), 15 (Ed25519). DS digest types 1/2/4. Canonical RDATA covers every supported RR type with embedded-name lowercasing (RFC 4034 §6.2) and automatic wildcard label-count reconstruction (§3.1.3). Negative-answer building blocks shipped: `canonicalNameCompare` (§6.1), `nsecCovers` (with zone-wrap-around), `nsec3Hash` (RFC 5155 §5 SHA-1 with iterations), `nsec3CoversHash`, `base32hexEncode`. Composing them into a full NXDOMAIN/NODATA proof and the chain-of-trust traversal belong in the recursive resolver layer.
- AXFR zone transfer (RFC 5936) — `Zone` class for in-memory zones, `AxfrClient` for fetching, `send(Packet[])` server hook for serving
- IXFR incremental zone transfer (RFC 1995) — `Zone.toIxfrPackets` with optional `ZoneChangeSet` history, `IxfrClient` returning a no-change / incremental / AXFR-fallback discriminated union
- NOTIFY zone-change notification (RFC 1996) — `NotifyClient` on the primary side, opcode-dispatch on the secondary side
- DNS UPDATE (RFC 2136) — `UpdateBuilder` fluent API, `Update.applyToZone` reference engine, `UpdateClient` over UDP/TCP/TLS
- 0x20 query-name case randomization (RFC 5452) and bailiwick filtering — opt-in spoofing and cache-poisoning defenses

<hr>

### Features

+ Server and Client
+ Lot of Type Supported
+ Extremely lightweight
+ DNS over UDP, TCP, TLS (DoT), HTTPS (DoH) — Server and Client

### Installation

```bash
$ npm install git+https://github.com/stefanwerfling/node-dns.git#ts
```

### Documentation

In-depth guides per topic live under [`docs/`](docs/README.md):

- **[DNS clients](docs/dns-clients.md)** — UDP, TCP, DoT, DoH, Google JSON,
  the combined `DNS` resolver, and the AXFR client. Truncation fallback,
  TLS options, ECS, per-query overrides.
- **[DNS servers](docs/dns-servers.md)** — `UDPServer`, `TCPServer`,
  `TLSServer` (DoT), `DohServer`, the combined `DnsServer`. Request event,
  `send` callback (single or `Packet[]`), pre-hooks, lifecycle.
- **[Record types](docs/record-types.md)** — every supported RR type with
  fields, construction examples, and unsupported-type fallback.
- **[EDNS(0) options](docs/edns.md)** — ECS, Cookies (incl. RFC 9018
  server-cookie algorithm), Padding, NSID, TCP Keepalive, Extended DNS
  Errors.
- **[TSIG](docs/tsig.md)** — transaction-signature signing/verification,
  fudge window, request-MAC chaining.
- **[Subdomain delegation](docs/subdomain-delegation.md)** — DNS structure
  with NS records: how to delegate `lab.example.com` to your own dns2ts
  server, glue records, multi-NS setups with NOTIFY/AXFR, sub-delegation,
  verification, and common pitfalls.
- **[Secure domain with desec.io](docs/secure-domain-with-desec.md)** —
  free DNSSEC via desec.io as the parent service, full email-security
  record set (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DANE/TLSA), and a
  subdomain delegated to your own dns2ts server.
- **[Becoming a TLD](docs/becoming-a-tld.md)** — what's actually involved
  in operating a public TLD: ICANN gTLD process, IETF special-use names,
  private/alternative roots, registry-operator obligations (DNSSEC, EPP,
  RDAP, escrow), where dns2ts fits, and full link/RFC reference list.
- **[Becoming a registrar](docs/becoming-a-registrar.md)** — the
  domain-selling tier: ICANN-accredited gTLD registrar, ccTLD-only direct,
  or reseller via OpenSRS / eNom / ResellerClub (the path most launches
  actually take). Costs, RAA obligations, EPP/WHOIS/RDAP touchpoints,
  where dns2ts handles the DNS-hosting value-add.
- **[Zone files](docs/zone-files.md)** — RFC 1035 master file parser and
  the `Zone` class. Directives, inheritance rules, supported RDATA, errors.
- **[AXFR](docs/axfr.md)** — full zone transfer over TCP/TLS using `Zone`
  and `AxfrClient`. Authentication patterns (TSIG, IP allow-list).
- **[IXFR](docs/ixfr.md)** — incremental zone transfer (RFC 1995) with
  `ZoneChangeSet` history, `Zone.toIxfrPackets`, and `IxfrClient` (no-change
  / incremental / AXFR-fallback).
- **[NOTIFY](docs/notify.md)** — RFC 1996 zone-change notification with
  `NotifyClient` (primary side) and an opcode-dispatching handler
  (secondary side).
- **[DNS UPDATE](docs/update.md)** — RFC 2136 dynamic updates: five
  prerequisite forms, four update forms, `UpdateBuilder` fluent API,
  `Update.applyToZone` reference engine, `UpdateClient` over UDP/TCP/TLS.
- **[PROXY protocol](docs/proxy-protocol.md)** — v1/v2 hooks for UDP and
  TCP/TLS, custom processors.
- **[Reverse proxy](docs/reverse-proxy.md)** — putting nginx, HAProxy, or
  Envoy in front of a dns2ts server. TLS termination vs pass-through,
  PROXY-protocol IP transparency, complete configs, troubleshooting.
- **[Security hardening](docs/security-hardening.md)** — 0x20 query-name
  case randomization (`Random0x20`, `use0x20: true`) and bailiwick
  filtering (`Bailiwick.contains`, `Bailiwick.filter`) against off-path
  spoofing and cache poisoning.
- **[DNSSEC validation](docs/dnssec.md)** — `Dnssec.verifyRrsig`,
  `Dnssec.verifyDs`, `Dnssec.computeKeyTag`, `Dnssec.computeDsDigest`. RFC
  4034/4035 algorithms 8/10/13/14/15, DS digest types 1/2/4. Stateless —
  no resolver, no cache; chain-of-trust walking is the caller's job.

### DNS Client (default UDP)

Lookup any records available for the domain `google.com`.
DNS client will use UDP by default.

```ts
import {DNS} from 'dns2ts';

const dns = new DNS({
  // dns server port (number)
  // port: 53,
  // Recursion Desired flag (boolean, default true)
  // recursive: true,
});

const result = await dns.resolveA('google.com');
console.log(result.answers);
```

Another way to use the UDP Client directly:

```ts
import {UDPClient, PacketTypes, PacketClass} from 'dns2ts';

const resolve = UDPClient.request({dns: '8.8.8.8'});

const response = await resolve('google.com', PacketTypes.A, PacketClass.IN);
console.log(response.answers);
```

When the UDP server sets the TC (truncation) bit in the response header, the
`UDPClient` automatically retries the same query over TCP against the same
nameserver (RFC 7766 §8). This is on by default; opt out with
`tcpFallback: false`, override the port with `tcpFallbackPort`:

```ts
UDPClient.request({
  dns: '1.1.1.1',
  port: 53,
  tcpFallback: true,       // default
  tcpFallbackPort: 53      // default: same as UDP port
});
```

### DNS Client (TCP)

```ts
import {TCPClient, PacketTypes, PacketClass} from 'dns2ts';

const resolve = TCPClient.request({dns: '8.8.8.8'});

try {
  const response = await resolve('lsong.org', PacketTypes.A, PacketClass.IN);
  console.log(response.answers);
} catch(error) {
  // some DNS servers (i.e cloudflare 1.1.1.1, 1.0.0.1)
  // may send an empty response when using TCP
  console.log(error);
}
```

### DNS Client (DNS over HTTPS)

```ts
import {DohClient, PacketTypes, PacketClass} from 'dns2ts';

const resolve = DohClient.request({dns: 'https://dns.google/dns-query'});

const response = await resolve('google.com', PacketTypes.A, PacketClass.IN);
console.log(response.answers);
```

### Client Custom DNS Server

You can pass your own DNS Server.

```ts
import {TCPClient, PacketTypes, PacketClass} from 'dns2ts';

const resolve = TCPClient.request({dns: '1.1.1.1'});

const result = await resolve('google.com', PacketTypes.A, PacketClass.IN);
console.log(result.answers);
```

### Example Server

```ts
import {DnsServer, Packet, PacketResource, PacketClass} from 'dns2ts';
import {A} from 'dns2ts';

const server = new DnsServer({
  udp: true,
  handle: (request, send) => {
    const response = Packet.createResponseFromRequest(request);
    const [question] = request.questions;

    response.answers.push(
      Packet.createResourceFromQuestion(question, new A('8.8.8.8'))
    );

    send(response);
  }
});

server.on('request', (request) => {
  console.log(request.header.id, request.questions[0]);
});

server.on('requestError', (error) => {
  console.log('Client sent an invalid request', error);
});

server.on('listening', () => {
  console.log(server.addresses());
});

server.on('close', () => {
  console.log('server closed');
});

server.listen({
  // Optionally specify port and/or address for udp server:
  udp: {
    port: 5333,
    address: '127.0.0.1',
  },

  // Optionally specify port and/or address for tcp server:
  tcp: {
    port: 5333,
    address: '127.0.0.1',
  },
});

// eventually
server.close();
```

Then you can test your DNS server:

```bash
$ dig @127.0.0.1 -p5333 lsong.org
```

Note that when implementing your own lookups, the contents of the query
will be found in `request.questions[0].name`.

### DNS over TLS server (DoT, RFC 7858)

`TLSServer` is a TLS-wrapped variant of `TCPServer` — same length-prefixed
framing and `request` event flow, but the connection is encrypted on port 853
with a certificate of your choice. The same `preRequest` / `preConnection`
hooks apply (typed for `tls.TLSSocket`).

```ts
import {readFileSync} from 'fs';
import {DnsServer, Packet} from 'dns2ts';

const server = new DnsServer({
  tcp: true,
  tls: {
    options: {
      cert: readFileSync('server.crt'),
      key:  readFileSync('server.key'),
    },
  },
  handle: (request, send) => {
    send(Packet.createResponseFromRequest(request));
  },
});

server.listen({tls: 853, tcp: 53});
```

The combined server reports separate addresses per transport via
`server.addresses()` (`addresses.tls` is the DoT listener). Use the existing
`TCPClient` with `protocol: ClientOptionsProtocol.tls` to query a DoT server.

### EDNS(0) options

EDNS records are built with `EDNS.createResource([...options])`. Each option
implements the `EdnsOption` interface; mix and match in one record:

```ts
import {
  EDNS, EdnsECS, EdnsCookie, EdnsPadding, EdnsNsid,
  EdnsKeepalive, EdnsExtendedError, ExtendedDnsErrorCode,
} from 'dns2ts';

const opt = EDNS.createResource([
  new EdnsECS('192.0.2.0/24'),                             // RFC 7871
  new EdnsCookie(EdnsCookie.generateClientCookie()),       // RFC 7873
  new EdnsPadding(128),                                    // RFC 7830
  new EdnsNsid(),                                          // RFC 5001 query
  new EdnsKeepalive(null),                                 // RFC 7828 client signal
  new EdnsExtendedError(ExtendedDnsErrorCode.STALE_ANSWER, 'cache hit'),
]);

packet.additionals.push(opt);
```

For server-side DNS Cookies, `EdnsCookie` provides RFC 9018-style helpers:

```ts
import {EdnsCookie} from 'dns2ts';

const secret = readFileSync('cookie-secret.bin'); // long-lived, ≥16 bytes

// Verify a cookie sent by the client
const ok = EdnsCookie.verifyServerCookie(
  cookieFromQuery.serverCookie!,
  cookieFromQuery.clientCookie,
  clientIpBytes,         // 4 bytes for IPv4, 16 for IPv6
  secret,
  {maxAgeSeconds: 3600}, // optional: reject cookies older than 1 hour
);

// Issue a fresh server cookie back to the client
const fresh = EdnsCookie.computeServerCookie(
  cookieFromQuery.clientCookie,
  clientIpBytes,
  secret,
);
```

`computeServerCookie` returns 24 bytes (1B version + 3B reserved + 4B unix
timestamp + 16B truncated HMAC-SHA256). `verifyServerCookie` recomputes with
the embedded timestamp and compares in constant time.

### Zone file parser (RFC 1035 master file format)

`ZoneParser.parse(text, options?)` turns a BIND-style zone file into an array
of `PacketResource` objects. Comments, parens-spanned records, quoted strings,
`$ORIGIN`/`$TTL` directives and `@` are all supported; owner-name inheritance
follows RFC 1035 §5.1 (a line that begins with whitespace inherits the owner
name from the previous record).

```ts
import {ZoneParser} from 'dns2ts';

const text = `
$ORIGIN example.com.
$TTL 3600
@   IN SOA ns1 admin (
        2024010101  ; serial
        7200        ; refresh
        3600        ; retry
        1209600     ; expire
        3600 )      ; minimum
    IN NS  ns1
    IN MX  10 mail
www IN A   192.0.2.1
www IN AAAA 2001:db8::1
`;

const {origin, records} = ZoneParser.parse(text);
console.log(origin);             // 'example.com.'
console.log(records.length);     // 5
```

RDATA parsers ship for 21 record types: A, AAAA, NS, CNAME, DNAME, PTR, MX,
TXT, SOA, SRV, CAA, DNSKEY, DS, SSHFP, TLSA, NAPTR, NSEC, NSEC3, RRSIG, SVCB,
HTTPS. Generic `TYPEnnn` mnemonics from RFC 3597 are accepted in NSEC/NSEC3
type bit maps. Unsupported types throw a descriptive error with the offending
line number rather than silently dropping data.

### AXFR zone transfer (RFC 5936)

`Zone` is the in-memory representation of a parsed zone (origin + records +
SOA helpers). `AxfrClient` opens a TCP (or TLS) connection, sends one
`QTYPE=AXFR` query, and reassembles the multi-message stream until the
closing SOA. The server-side hook accepts `Packet[]` so a single handler
call can emit the full transfer.

```ts
import {DnsServer, Zone, AxfrClient} from 'dns2ts';

const zone = Zone.fromZoneFile(`
$ORIGIN example.com.
$TTL 3600
@   IN SOA ns1 admin (2024010101 7200 3600 1209600 3600)
@   IN NS  ns1
@   IN MX  10 mail
www IN A   192.0.2.1
`);

// Authoritative server: serve AXFR for the zone
const server = new DnsServer({
  tcp: true,
  handle: (request, send) => {
    if (request.questions[0]?.type === 252 /* AXFR */) {
      send(zone.toAxfrPackets(request));   // multi-message reply
      return;
    }
    // … normal A/AAAA/MX/… handling …
  },
});
const {tcp} = await server.listen();

// Fetch the zone with the client
const transfer = AxfrClient.request({dns: '127.0.0.1', port: tcp.port});
const {soa, records} = await transfer('example.com');
console.log(soa.packetType.serial, records.length);
```

`zone.toAxfrPackets(query)` currently emits the simplest valid AXFR shape
(RFC 5936 §2.2): one response message that begins and ends with the SOA.
Multi-message splitting for zones whose serialized form would exceed 64 KiB
is not yet implemented — split the records yourself and call
`send([packet1, packet2, …])` for very large zones.

### TSIG (transaction signatures, RFC 8945)

Sign outgoing queries and verify incoming responses with a shared-secret HMAC.
Supported algorithms: `hmac-md5`, `hmac-sha1`, `hmac-sha224`, `hmac-sha256`
(default), `hmac-sha384`, `hmac-sha512`. Uses Node's built-in `crypto` — no
extra dependencies.

```ts
import {Packet, PacketQuestion, PacketTypes, PacketClass,
        Tsig, TsigKey, TsigAlgorithm} from 'dns2ts';

const key = new TsigKey('my-key.', TsigAlgorithm.HMAC_SHA256, 'base64-secret');

// Sign an outgoing query
const query = new Packet();
query.questions.push(new PacketQuestion('example.com', PacketTypes.A, PacketClass.IN));
const {buffer: wire, mac: requestMac} = Tsig.sign(query, key);

// … send `wire` over the wire, receive `responseBytes` …

// Verify the signed response
const parsed = Packet.parse(responseBytes);
const result = Tsig.verify(parsed, responseBytes, key, {requestMac: requestMac});
if (!result.valid) {
  throw new Error(`TSIG check failed: ${result.reason}`);
}
```

`Tsig.verify` enforces the fudge window (`|now − timeSigned| ≤ fudge`) by default
and compares MACs in constant time. Pass `skipTimeCheck: true` when replaying
recorded traffic. `Tsig.sign` accepts `requestMac` to chain responses
(RFC 8945 §5.3.2.3).

### PROXY protocol support

When the server sits behind a load balancer or proxy (HAProxy, AWS NLB, Envoy,
…) the original client IP is normally hidden. Configure a PROXY protocol
processor so each packet/connection gets its real source endpoint restored
before your handler is invoked.

- UDP uses a per-datagram `preRequest` processor.
- TCP uses a per-connection `preConnection` processor (the header appears
  once, before any DNS data).

```ts
import {
  DnsServer,
  ProxyProtocolV2,      // UDP, per datagram
  ProxyProtocolV2Tcp    // TCP, once per connection
} from 'dns2ts';

const server = new DnsServer({
  udp: { preRequest:    new ProxyProtocolV2() },
  tcp: { preConnection: new ProxyProtocolV2Tcp() },
  handle: (request, send, client) => {
    // UDP: `client` is `dgram.RemoteInfo` with the real source address/port.
    // TCP: `client` is the `net.Socket`; its `remoteAddress`/`remotePort`
    // are shadowed with the proxied endpoint, so `client.remoteAddress`
    // returns the real client IP (responses still flow through the proxy).
    console.log('real client:', client);
    send(Packet.createResponseFromRequest(request));
  }
});
```

Classes shipped:

| Class                  | Transport | Interface                            |
| ---------------------- | --------- | ------------------------------------ |
| `ProxyProtocolV1`      | UDP       | `ServerPreRequest<dgram.RemoteInfo>` |
| `ProxyProtocolV2`      | UDP       | `ServerPreRequest<dgram.RemoteInfo>` |
| `ProxyProtocolV1Tcp`   | TCP       | `ServerPreConnection<net.Socket>`    |
| `ProxyProtocolV2Tcp`   | TCP       | `ServerPreConnection<net.Socket>`    |

Each v1/v2 class also exposes static `detect(buffer)`, `parse(buffer)` and
`bytesNeeded(buffer)` for use outside of the server hooks.

### Custom pre-request / pre-connection hooks

The same hooks are generic — implement your own processor to strip custom
framing, collect metrics or override the client reference. Interfaces are
`ServerPreRequest<TClient>` (per message) and `ServerPreConnection<TClient>`
(per TCP connection).

```ts
import {ServerPreRequest, ServerPreRequestResult} from 'dns2ts';
import type {RemoteInfo} from 'dgram';

class MyStripper implements ServerPreRequest<RemoteInfo> {
  async process(data: Buffer, client: RemoteInfo): Promise<ServerPreRequestResult<RemoteInfo>> {
    // strip a custom prefix, return modified buffer and/or overridden client
    return { data: data.subarray(8), client: { ...client, address: 'real.ip' } };
  }
}
```

### DNSSEC validation (RFC 4034 / 4035)

`Dnssec` is a stateless verification layer — feed it an RRset, the matching
RRSIG, and a candidate DNSKEY, and it returns a boolean. There is no
resolver, no cache, no chain traversal; that lives one layer up.

Supported signing algorithms: 8 (RSA/SHA-256), 10 (RSA/SHA-512), 13 (ECDSA
P-256), 14 (ECDSA P-384), 15 (Ed25519). DS digest types: 1 (SHA-1),
2 (SHA-256), 4 (SHA-384). Public-key parsing goes via Node's JWK import,
so there's no PEM detour.

```ts
import {Dnssec} from 'dns2ts';

// Validate an RRset against an RRSIG using one DNSKEY
const ok = Dnssec.verifyRrsig(
  'example.com',           // owner name (canonical form is computed for you)
  rrset,                   // PacketResource[] — the RRset that was signed
  rrsig,                   // RRSIG record with signer, expiration, signature
  dnskey,                  // candidate DNSKEY
  {
    // optional: override "now" for the inception/expiration window check
    // now: 1735689600,
    // optional: skip the time window check entirely
    // skipValidityWindow: true,
  }
);

// Verify a DNSKEY against its DS at the parent zone
const matches = Dnssec.verifyDs('example.com', dnskey, ds);

// Compute the RFC 4034 Appendix B key tag for a DNSKEY
const keyTag = Dnssec.computeKeyTag(dnskey);

// Compute the DS digest yourself (for emitting a DS record)
const digest = Dnssec.computeDsDigest('example.com', dnskey, 2 /* SHA-256 */);
```

Canonical RDATA encoding covers every supported record type — wire-already-
canonical types (A, AAAA, DS, DNSKEY, TXT, SPF, CAA, TLSA, SSHFP, NSEC3) use
their wire-format encode as-is, and embedded-name types (NS, CNAME, DNAME,
PTR, MX, SOA, SRV, NAPTR, NSEC, RRSIG) re-emit with names lowercased and
uncompressed per RFC 4034 §6.2. RFC 4034 §3.1.3 wildcard label-count
reconstruction is automatic: when `rrsig.labels` is less than the owner's
actual label count, the validator infers `*.<trailing labels>` as the
signed owner before hashing.

### Signing your own zones

`signRrset` is the inverse of `verifyRrsig` — same canonical-form
construction on both sides, so a signature you produce here verifies
through the verifier in this library by construction. Algorithms
8/10/13/14/15 are supported.

```ts
import * as crypto from 'crypto';
import {Dnssec, DnssecAlgorithm} from 'dns2ts';

// 1. Generate a key pair (KSK or ZSK — same code path)
const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');

// 2. Wrap the public key in a DNSKEY ready to publish
const dnskey = Dnssec.publicKeyToDnskey(publicKey, DnssecAlgorithm.ED25519);

// 3. Sign an RRset
const rrsig = Dnssec.signRrset(
  'example.com',                  // owner
  rrset,                          // PacketResource[]
  dnskey,                         // for algorithm + key tag
  privateKey,                     // matching private key
  {
    inception: '20240101000000',
    expiration: '20300101000000',
    // optional overrides:
    //   originalTtl: 3600,
    //   signer: 'example.com',
    //   labels: 2,        // override for wildcard owners
  }
);
```

`inception` / `expiration` accept either the RFC 4034 §3.2
`YYYYMMDDHHMMSS` UTC form or unix-decimal seconds (string or number);
both are normalized to YYYYMMDDHHMMSS on the returned RRSIG.
`publicKeyToDnskey` produces RFC-3110-format RSA, raw-point ECDSA, or
32-byte raw Ed25519 wire formats from a Node `KeyObject`. Wildcard
signing: pass `labels: 2` (or whatever the wildcard count is) so the
verifier reconstructs `*.<trailing>` for any expansion.

For negative answers, NSEC and NSEC3 building blocks are shipped:

```ts
// NSEC: does the chain entry at `owner` (with NextDomain `next`) prove
// `query` doesn't exist? Handles the end-of-zone wrap-around case.
Dnssec.nsecCovers(ownerName, nextDomain, queryName);    // boolean

// Canonical DNS name order (RFC 4034 §6.1) for sorting an NSEC chain
Dnssec.canonicalNameCompare(a, b);                      // -1 / 0 / +1

// NSEC3: hash a name per RFC 5155 §5 (SHA-1, iterations + 1 calls)
const queryHash = Dnssec.nsec3Hash('host.example.com', 'aabbccdd', 12);

// Compare hashes against a chain entry's owner / nextHashedOwner
Dnssec.nsec3CoversHash(ownerHashBuf, nextHashBuf, queryHash);   // boolean

// Render a hash as the base32hex label that NSEC3 owner names use
const label = Dnssec.base32hexEncode(queryHash);
```

These are deliberately primitives — composing them into a full NXDOMAIN
or NODATA proof (closest-encloser + next-closer + wildcard) lives one
layer up in the recursive resolver, where the answer's structure
provides the closest-encloser candidate.

See [`docs/dnssec.md`](docs/dnssec.md) for the deeper guide and the current
limitations (no end-to-end NXDOMAIN composer, no chain-of-trust walk, no
zone signing).

### Build & Development

```bash
npm install       # Install dev dependencies
npx tsc           # Compile TypeScript (src/ -> dist/)
npm test          # Compile and run tests
npm run lint      # ESLint check
```

### Relevant Specifications

+ [RFC-1034 - Domain Names - Concepts and Facilities](https://tools.ietf.org/html/rfc1034)
+ [RFC-1035 - Domain Names - Implementation and Specification](https://tools.ietf.org/html/rfc1035)
+ [RFC-2782 - A DNS RR for specifying the location of services (DNS SRV)](https://tools.ietf.org/html/rfc2782)
+ [RFC-3110 - RSA/SHA-1 SIGs and RSA KEYs in the Domain Name System (DNS)](https://datatracker.ietf.org/doc/html/rfc3110) (RSA public-key wire format reused by DNSKEY)
+ [RFC-3597 - Handling of Unknown DNS Resource Record (RR) Types](https://datatracker.ietf.org/doc/html/rfc3597) (generic `TYPEnnn` mnemonic)
+ [RFC-4034 - Resource Records for the DNS Security Extensions (DNSSEC)](https://tools.ietf.org/html/rfc4034)
+ [RFC-4035 - Protocol Modifications for the DNS Security Extensions](https://datatracker.ietf.org/doc/html/rfc4035) (validation requirements)
+ [RFC-4509 - Use of SHA-256 in DNSSEC Delegation Signer (DS) Resource Records](https://datatracker.ietf.org/doc/html/rfc4509)
+ [RFC-4648 - The Base16, Base32, and Base64 Data Encodings](https://datatracker.ietf.org/doc/html/rfc4648) (base32hex for NSEC3)
+ [RFC-5155 - DNS Security (DNSSEC) Hashed Authenticated Denial of Existence](https://datatracker.ietf.org/doc/html/rfc5155) (NSEC3 wire format, presentation, and SHA-1 hash with iterations)
+ [RFC-9276 - Guidance for NSEC3 Parameter Settings](https://datatracker.ietf.org/doc/html/rfc9276) (only NSEC3 hash algorithm 1 / SHA-1 is allowed in production)
+ [RFC-6605 - Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC](https://datatracker.ietf.org/doc/html/rfc6605) (ECDSA P-256 / P-384)
+ [RFC-6840 - Clarifications and Implementation Notes for DNS Security (DNSSEC)bis](https://datatracker.ietf.org/doc/html/rfc6840) (no-compression rule for DNSSEC RRs)
+ [RFC-8080 - Edwards-Curve DSA for DNSSEC](https://datatracker.ietf.org/doc/html/rfc8080) (Ed25519 / Ed448)
+ [RFC-5001 - DNS Name Server Identifier (NSID) Option](https://datatracker.ietf.org/doc/html/rfc5001)
+ [RFC-6672 - DNAME Redirection in the DNS](https://datatracker.ietf.org/doc/html/rfc6672)
+ [RFC-6891 - Extension Mechanisms for DNS (EDNS(0))](https://tools.ietf.org/html/rfc6891)
+ [RFC-7766 - DNS Transport over TCP - Implementation Requirements](https://tools.ietf.org/html/rfc7766) (includes §8 truncation fallback)
+ [RFC-7828 - The edns-tcp-keepalive EDNS(0) Option](https://datatracker.ietf.org/doc/html/rfc7828)
+ [RFC-7830 - The EDNS(0) Padding Option](https://datatracker.ietf.org/doc/html/rfc7830)
+ [RFC-7858 - Specification for DNS over Transport Layer Security (DoT)](https://datatracker.ietf.org/doc/html/rfc7858)
+ [RFC-7871 - Client Subnet in DNS Queries](https://tools.ietf.org/html/rfc7871)
+ [RFC-7873 - Domain Name System (DNS) Cookies](https://datatracker.ietf.org/doc/html/rfc7873)
+ [RFC-8484 - DNS Queries over HTTPS (DoH)](https://tools.ietf.org/html/rfc8484)
+ [RFC-8914 - Extended DNS Errors](https://datatracker.ietf.org/doc/html/rfc8914)
+ [RFC-8945 - Secret Key Transaction Authentication for DNS (TSIG)](https://datatracker.ietf.org/doc/html/rfc8945)
+ [RFC-1995 - Incremental Zone Transfer in DNS (IXFR)](https://datatracker.ietf.org/doc/html/rfc1995)
+ [RFC-1996 - A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)](https://datatracker.ietf.org/doc/html/rfc1996)
+ [RFC-2136 - Dynamic Updates in the Domain Name System (DNS UPDATE)](https://datatracker.ietf.org/doc/html/rfc2136)
+ [RFC-5936 - DNS Zone Transfer Protocol (AXFR)](https://datatracker.ietf.org/doc/html/rfc5936)
+ [RFC-9018 - Interoperable Domain Name System (DNS) Server Cookies](https://datatracker.ietf.org/doc/html/rfc9018)
+ [RFC-9460 - Service Binding and Parameter Specification via the DNS (SVCB, HTTPS)](https://datatracker.ietf.org/doc/html/rfc9460)

### Contributing

- Fork this Repo first
- Clone your Repo
- Install dependencies by `$ npm install`
- Checkout a feature branch
- Feel free to add your features
- Make sure your features are fully tested
- Publish your local branch, Open a pull request
- Enjoy hacking <3

### MIT license

Copyright (c) 2016 LIU SONG <song940@gmail.com> & [contributors](https://github.com/song940/node-dns/graphs/contributors).

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.