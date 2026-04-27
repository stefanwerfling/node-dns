# PROXY protocol

The PROXY protocol is a small preamble that a load balancer or reverse
proxy prepends to a connection (or datagram) so the backend can see the
*original* client endpoint instead of the proxy's. Without it, every
client looks like it's connecting from the proxy's IP.

dns2ts implements both versions: v1 (text) and v2 (binary). For full
deployment context — nginx, HAProxy, Envoy configurations — see the
[reverse-proxy guide](reverse-proxy.md). This file documents the in-process
hook API.

## Two flavours, two hooks

PROXY protocol applies once per *flow*. The shape of "a flow" differs by
transport:

- **TCP/TLS**: one preamble per *connection*, before any DNS framing. dns2ts
  exposes this as a `ServerPreConnection<net.Socket>` hook.
- **UDP**: one preamble per *datagram*, prepended to the DNS payload. dns2ts
  exposes this as a `ServerPreRequest<dgram.RemoteInfo>` hook.

| Class                  | Transport | Interface                            |
| ---------------------- | --------- | ------------------------------------ |
| `ProxyProtocolV1`      | UDP       | `ServerPreRequest<dgram.RemoteInfo>` |
| `ProxyProtocolV2`      | UDP       | `ServerPreRequest<dgram.RemoteInfo>` |
| `ProxyProtocolV1Tcp`   | TCP/TLS   | `ServerPreConnection<net.Socket>`    |
| `ProxyProtocolV2Tcp`   | TCP/TLS   | `ServerPreConnection<net.Socket>`    |

Pick a version (v2 is the modern default; v1 is text-mode legacy) and
attach the hook to the matching protocol block.

## TCP / TLS — per-connection

```ts
import {DnsServer, ProxyProtocolV2Tcp, ProxyProtocolV1Tcp} from 'dns2ts';

const server = new DnsServer({
  tcp: { preConnection: new ProxyProtocolV2Tcp() },
  // tls: { options: { cert, key }, preConnection: new ProxyProtocolV2Tcp() },
  handle: (request, send, client) => {
    const sock = client as net.Socket;
    // sock.remoteAddress / sock.remotePort are now the real client endpoint,
    // shadowed via Object.defineProperty before your handler is invoked.
    console.log('real client:', sock.remoteAddress, sock.remotePort);
    send(/* … */);
  },
});
```

The hook reads the PROXY header off the socket, parses it, overrides
`remoteAddress` and `remotePort` on the socket via `Object.defineProperty`,
and feeds any leftover bytes (the start of the actual DNS framing) into the
server's normal length-prefix reader. Your handler sees the real client
endpoint without any further work.

If a connection arrives **without** a PROXY header (or with a malformed
one), the connection is closed and a `requestError` is emitted. The
hook is strict by design — running with PROXY-enabled means the load
balancer must always send the header.

## UDP — per-datagram

```ts
import {DnsServer, ProxyProtocolV2, ProxyProtocolV1} from 'dns2ts';

const server = new DnsServer({
  udp: { preRequest: new ProxyProtocolV2() },
  handle: (request, send, rinfo) => {
    // rinfo.address / rinfo.port are the real client (after the proxy stripped them).
    console.log('real client:', rinfo.address, rinfo.port);
    send(/* … */);
  },
});
```

Each datagram must carry a PROXY header followed by the DNS message. Both
v1 and v2 work over UDP; v2 is recommended (binary, 16-byte fixed header).

Responses always go back to the *transport peer* (the proxy that sent the
datagram). Only the emitted `client` reference is rewritten — that way the
proxy can route the answer back to the client over its existing flow.

## v1 vs v2

Both versions ship in dns2ts; you can read both at the static-method level:

```ts
import {ProxyProtocolV1, ProxyProtocolV2} from 'dns2ts';

ProxyProtocolV1.detect(buffer);              // boolean: starts with "PROXY "?
ProxyProtocolV2.detect(buffer);              // boolean: starts with the v2 signature?

ProxyProtocolV1.parse(buffer);               // {info, rest}
ProxyProtocolV2.parse(buffer);               // {info, rest}

ProxyProtocolV1.bytesNeeded(buffer);         // null if more data needed, number if header complete
ProxyProtocolV2.bytesNeeded(buffer);         //  "
```

`info` is a `ProxyProtocolInfo` object with `version`, `command` (PROXY or
LOCAL), `family` (UNSPEC/INET/INET6/UNIX), `transport` (UNSPEC/STREAM/DGRAM)
and optional `source`/`destination` `{address, port}` pairs.

`rest` is the remainder of the input after the header. For TCP, this is
the start of the DNS length-prefixed framing; for UDP, it's the DNS
message.

### When to use v1

v1 (`PROXY TCP4 …`, ASCII) is human-readable and easy to debug with `nc`,
but is otherwise inferior to v2: longer header, no UDP, no TLV extensions.
Use v1 only when your upstream proxy doesn't speak v2.

### When to use v2

v2 is binary, fixed-size, supports both TCP and UDP, and carries optional
TLVs (e.g. ALPN, authority, AWS VPC endpoint id). dns2ts parses but does
not yet expose individual v2 TLVs — only the address block.

## Custom processors

The hook interfaces are generic — implement your own to strip a different
preamble or rewrite the client identity. Three examples follow.

### Strip a constant prefix

```ts
import {ServerPreRequest, ServerPreRequestResult} from 'dns2ts';
import type {RemoteInfo} from 'dgram';

class StripFourBytes implements ServerPreRequest<RemoteInfo> {
  async process(data: Buffer, client: RemoteInfo): Promise<ServerPreRequestResult<RemoteInfo>> {
    return {data: data.subarray(4), client: client};
  }
}
```

### Tag with metrics, leave data untouched

```ts
import {ServerPreRequest, ServerPreRequestResult} from 'dns2ts';
import type {RemoteInfo} from 'dgram';
import {metrics} from './metrics.js';

class ObserveOnly implements ServerPreRequest<RemoteInfo> {
  async process(data: Buffer, client: RemoteInfo): Promise<ServerPreRequestResult<RemoteInfo>> {
    metrics.incr('dns.requests', {src: client.address});
    return {data: data};
  }
}
```

### TCP per-connection: consume a custom handshake

```ts
import {ServerPreConnection, ServerPreConnectionResult, SocketReader} from 'dns2ts';
import net from 'net';

class CustomHandshakeTcp implements ServerPreConnection<net.Socket> {
  async process(client: net.Socket): Promise<ServerPreConnectionResult<net.Socket>> {
    // Read N bytes off the socket, validate, optionally rewrite address.
    // The library helper `ProxyProtocolTcpReader` shows the incremental
    // socket-reading pattern; mirror it here.
    return {
      client: client,                     // possibly with overridden remoteAddress/remotePort
      initialBuffer: Buffer.alloc(0),     // any bytes already read past your preamble
    };
  }
}
```

The `initialBuffer` field is what makes streaming preambles work: any
bytes you read past the preamble are fed back into `SocketReader.readStream`
so the DNS length-prefix parser doesn't miss the start of the first message.

## Composing with TLS

`ProxyProtocolV2Tcp` and friends operate on the raw socket, so attaching
them to a `TLSServer` block intercepts the bytes **before TLS starts**.
That's correct for a load-balancer that emits a PROXY preamble in front of
TLS (HAProxy `send-proxy-v2`, AWS NLB).

If your load balancer terminates TLS itself and re-encrypts to the
backend, the PROXY header arrives on the inner TCP stream — same hook
attached to `tcp` works.

## Troubleshooting

- **`unmatched PROXY` / `expected v2 signature` errors**: the proxy isn't
  sending the header you expect. Check the proxy config (`send-proxy`,
  `send-proxy-v2`, `proxy_protocol on;`).
- **Client IP is the proxy IP**: hook missing or attached to the wrong
  protocol block. Verify with `console.log(client.remoteAddress)` in the
  handler.
- **First DNS request hangs / never arrives**: the socket framing got
  desynchronized — usually the proxy sent the v1 header but you wired up
  v2 (or vice-versa). The two preambles are visually distinct; check
  `nc -l 5300 | xxd` to see what arrives.
- **Tests with self-rolled PROXY headers fail**: `ProxyProtocolV2.SIGNATURE`
  is the canonical 12-byte signature; build the rest of the header by hand
  per RFC, paying attention to byte order. The integration tests in
  `Test/serverIntegration.ts` show working examples.