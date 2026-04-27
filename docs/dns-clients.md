# DNS clients

dns2ts ships five DNS client classes plus a combined resolver. Every client
exposes a static `request(options)` that returns an async resolver function
`(name, type, class, options?) => Promise<Packet>`. The resolver function is
created once, then called per query — useful for connection reuse or for
running the same configuration against many names.

| Class         | Transport               | Default port | Module          |
| ------------- | ----------------------- | -----------: | --------------- |
| `UDPClient`   | UDP (with TCP fallback) | 53           | `dns2ts`        |
| `TCPClient`   | TCP or TLS              | 53 / 853     | `dns2ts`        |
| `DohClient`   | HTTP / HTTPS / HTTP/2   | 80 / 443     | `dns2ts`        |
| `GoogleClient`| Google DNS JSON API     | 443 (HTTPS)  | `dns2ts`        |
| `AxfrClient`  | TCP or TLS              | 53 / 853     | `dns2ts`        |
| `DNS`         | All of the above        | per server   | `dns2ts`        |

## UDPClient

```ts
import {UDPClient, PacketTypes, PacketClass} from 'dns2ts';

const resolve = UDPClient.request({dns: '8.8.8.8'});
const response = await resolve('example.com', PacketTypes.A, PacketClass.IN);

console.log(response.answers);
```

### Truncation fallback (RFC 7766 §8)

When the server sets the `TC` bit on the UDP response, `UDPClient` retries
the same query over TCP automatically. This is on by default.

```ts
UDPClient.request({
  dns: '1.1.1.1',
  port: 53,
  tcpFallback: true,        // default; set to false to return the truncated UDP reply
  tcpFallbackPort: 53       // default: same as the UDP port
});
```

When `tcpFallback: false`, the truncated UDP `Packet` is returned as-is —
`response.header.tc === 1` and the answer section will typically be empty.

### Adding EDNS Client Subnet

```ts
import {UDPClient, PacketTypes, PacketClass} from 'dns2ts';

const resolve = UDPClient.request({dns: '8.8.8.8'});
const response = await resolve('example.com', PacketTypes.A, PacketClass.IN, {
  clientIp: '203.0.113.0/24'   // ECS hint forwarded to the recursor
});
```

## TCPClient

TCP and TLS share the same client class — the protocol is selected via
`ClientOptionsProtocol`.

```ts
import {TCPClient, ClientOptionsProtocol, PacketTypes, PacketClass} from 'dns2ts';

// Plain TCP
const tcp = TCPClient.request({dns: '1.1.1.1'});
const a = await tcp('example.com', PacketTypes.A, PacketClass.IN);

// DNS over TLS (DoT, RFC 7858)
const dot = TCPClient.request({
  dns: 'dns.google',
  protocol: ClientOptionsProtocol.tls,
  port: 853,                     // default for TLS
});
const b = await dot('example.com', PacketTypes.A, PacketClass.IN);
```

The default port is **53 for TCP** and **853 for TLS**. The TLS variant uses
Node's default certificate store and SNI — the host portion of `dns` becomes
the SNI value.

If you need to talk to a self-signed DoT endpoint (lab, dev) the TCPClient
does not currently expose a `rejectUnauthorized` toggle; build the connection
manually with `tls.connect({rejectUnauthorized: false, ...})` and parse the
length-prefixed frame yourself, or set `NODE_TLS_REJECT_UNAUTHORIZED=0` for
local testing.

## DohClient

Resolves over DNS-over-HTTPS (RFC 8484) using POST with
`application/dns-message`. Supports HTTP/1.1, HTTP/2, and plain HTTP.

```ts
import {DohClient, PacketTypes, PacketClass} from 'dns2ts';

const resolve = DohClient.request({dns: 'https://dns.google/dns-query'});
const response = await resolve('example.com', PacketTypes.A, PacketClass.IN);
```

The URL must include the protocol (`https://` or `http://`). Path defaults
to whatever you give it; most public resolvers expect `/dns-query`.

## GoogleClient

Uses Google's JSON API at `https://dns.google/resolve`. Returns the same
`Packet`-shaped object the wire-format clients return, so it can drop into
the same code paths.

```ts
import {GoogleClient, PacketTypes, PacketClass} from 'dns2ts';

const resolve = GoogleClient.request();
const response = await resolve('example.com', PacketTypes.A, PacketClass.IN);
```

This client is convenient when wire-format access is blocked by a corporate
HTTP proxy that allows JSON over HTTPS.

## AxfrClient

Performs an AXFR full zone transfer (RFC 5936). TCP-only — UDP is not a
legal AXFR transport. See the [AXFR guide](axfr.md) for the full picture.

```ts
import {AxfrClient} from 'dns2ts';

const transfer = AxfrClient.request({dns: '127.0.0.1', port: 5300});
const {soa, records} = await transfer('example.com');
console.log(soa.packetType.serial, records.length);
```

Calling the returned function once consumes one TCP connection. The promise
resolves on the closing SOA and rejects if the connection closes early.

## DNS — the high-level resolver

`DNS` queries multiple nameservers in parallel and returns the first answer.
Useful for quick programs that don't want to think about transport.

```ts
import {DNS} from 'dns2ts';

const dns = new DNS({
  nameServers: ['1.1.1.1', '8.8.8.8'],
  recursive: true,            // default
});

const result = await dns.resolveA('example.com');
console.log(result.answers);
```

`DNS` also exposes per-type helpers (`resolveA`, `resolveAAAA`, `resolveMX`,
`resolveTxt`, …) that return the parsed `Packet`. Pass DoH/DoT addresses and
the matching protocol to use encrypted transports.

## Common options

All wire-format clients accept the same `ClientOptions` shape:

| Field             | Type                            | Notes                                    |
| ----------------- | ------------------------------- | ---------------------------------------- |
| `dns`             | `string`                        | Host or `host:port`                      |
| `port`            | `number?`                       | Override default                         |
| `protocol`        | `ClientOptionsProtocol?`        | Selects UDP/TCP/TLS                      |
| `tcpFallback`     | `boolean?` (UDP only)           | Default `true`                           |
| `tcpFallbackPort` | `number?` (UDP only)            | Defaults to the UDP port                 |

The resolver function then takes a per-query `options` argument:

| Field        | Type        | Notes                                            |
| ------------ | ----------- | ------------------------------------------------ |
| `clientIp`   | `string?`   | EDNS Client Subnet (RFC 7871)                    |
| `recursive`  | `boolean?`  | Default `true`                                   |