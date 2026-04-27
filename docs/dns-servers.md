# DNS servers

dns2ts ships four protocol-specific server classes plus a combined
multi-protocol server. They share the same `request` event shape and lifecycle,
so swapping transports rarely changes handler code.

| Class       | Transport           | Default port | Listening type        |
| ----------- | ------------------- | -----------: | --------------------- |
| `UDPServer` | UDP                 | -            | datagram              |
| `TCPServer` | TCP                 | -            | length-prefixed frames |
| `TLSServer` | DoT (RFC 7858)      | -            | TLS-wrapped TCP        |
| `DohServer` | DoH (RFC 8484)      | -            | HTTP/HTTPS             |
| `DnsServer` | All of the above    | per protocol | combined               |

You bind to whatever port you pass to `listen()` — there is no implicit `:53`
or `:853`. Real-world deployments commonly bind to high ports and put a
reverse proxy in front; see the [reverse-proxy guide](reverse-proxy.md).

## DnsServer (combined)

The simplest way to expose multiple transports at once:

```ts
import {DnsServer, Packet, PacketResource, PacketClass, A} from 'dns2ts';

const server = new DnsServer({
  udp: true,
  tcp: true,
  handle: (request, send, client) => {
    const [question] = request.questions;

    const response = Packet.createResponseFromRequest(request);
    response.questions = request.questions.slice();
    response.answers.push(
      new PacketResource(question.name, new A('192.0.2.1'), PacketClass.IN, 60),
    );

    send(response);
  },
});

const addresses = await server.listen({udp: 5333, tcp: 5333});
console.log(addresses);
// { udp: { address: '0.0.0.0', port: 5333, family: 'IPv4' },
//   tcp: { address: '0.0.0.0', port: 5333, family: 'IPv4' } }
```

`server.listen(options)` returns a promise that resolves once every enabled
transport has bound. Pass `0` (or omit) to let the OS pick a port — useful
in tests.

### Enabling DoT and DoH

```ts
import {readFileSync} from 'fs';
import {DnsServer} from 'dns2ts';

const server = new DnsServer({
  udp: true,
  tcp: true,
  tls: {                                          // DoT — port 853 conventionally
    options: {
      cert: readFileSync('server.crt'),
      key:  readFileSync('server.key'),
    },
  },
  doh: {                                          // DoH — port 443 conventionally
    ssl: true,
    options: {
      cert: readFileSync('server.crt'),
      key:  readFileSync('server.key'),
    },
    cors: '*',                                    // or false / a function
  },
  handle: (request, send) => {
    send(Packet.createResponseFromRequest(request));
  },
});

await server.listen({udp: 53, tcp: 53, tls: 853, doh: 443});
```

Once running, `server.addresses()` returns the bound endpoints per transport:

```ts
const addrs = server.addresses();
console.log(addrs.udp, addrs.tcp, addrs.tls, addrs.doh);
```

## The `request` event

Every server emits `request` with three arguments:

```ts
type RequestHandler = (
  request: Packet,
  send: (response: Packet | Packet[]) => void,
  client: unknown
) => void;
```

- `request` — the parsed `Packet`. `request.questions[0]` is normally what you
  care about.
- `send` — closes the response loop. Pass a single `Packet` for a typical
  reply or a `Packet[]` for multi-message exchanges (AXFR — TCP/TLS only;
  UDP only honours the first element).
- `client` — transport-specific:
  - UDP: `dgram.RemoteInfo` with `address`, `port`, `family`, `size`.
  - TCP / TLS: `net.Socket` (or `tls.TLSSocket`). `remoteAddress` and
    `remotePort` are the peer endpoint, possibly overridden by a PROXY
    protocol pre-hook.
  - DoH: `http.IncomingMessage`.

Two ways to attach a handler:

```ts
// Inline option
new DnsServer({udp: true, handle: (req, send) => send(/* … */)});

// Or via an event listener (multiple are supported)
const srv = new DnsServer({udp: true});
srv.on('request', (req, send, client) => send(/* … */));
```

## Building responses

`Packet.createResponseFromRequest(request)` is the convenience for the common
case — it sets `qr=1` and copies the header. **Caveat:** it shares the header
*reference* with the request. If you need to build several responses with
distinct header fields (e.g. distinct IDs for an AXFR-style burst), build
fresh `new Packet()` instances and copy what you need.

```ts
import {Packet, PacketResource, PacketClass, A} from 'dns2ts';

const response = Packet.createResponseFromRequest(request);
response.questions = request.questions.slice();   // most servers echo the question
response.answers.push(
  new PacketResource(request.questions[0].name, new A('192.0.2.1'), PacketClass.IN, 60),
);
send(response);
```

For `AA` (authoritative), `RA` (recursion available), `RCODE`, etc., set the
fields directly on `response.header` before calling `send`.

## Multi-message responses (AXFR)

`send` accepts an array — every element is written as a length-prefixed frame
before the connection is closed. Used by AXFR; see the [AXFR guide](axfr.md).

```ts
const server = new DnsServer({
  tcp: true,
  handle: (request, send) => {
    if (request.questions[0]?.type === 252 /* AXFR */) {
      send(zone.toAxfrPackets(request));
      return;
    }
    send(/* normal one-shot response */);
  },
});
```

UDP cannot stream multiple datagrams as one logical reply, so passing an
array on UDP sends only the first packet (matches the design of AXFR being
TCP-only — RFC 5936 §4.2).

## Pre-hooks

Two optional hook interfaces let you intercept traffic before it hits the
handler:

- `ServerPreRequest<TClient>` — runs once per parsed message (UDP datagram,
  TCP-framed message, DoH HTTP body). Can rewrite the buffer and override
  the emitted client reference.
- `ServerPreConnection<TClient>` — TCP/TLS only. Runs once per accepted
  connection, before any DNS framing is read. Can consume preamble bytes and
  expose the real source endpoint.

The most common use is PROXY protocol — see [proxy-protocol.md](proxy-protocol.md).

```ts
new DnsServer({
  tcp: { preConnection: new ProxyProtocolV2Tcp() },
  udp: { preRequest:    new ProxyProtocolV2() },
  handle,
});
```

Implement your own to strip a custom framing, collect metrics, or rewrite
the client identity:

```ts
import {ServerPreRequest, ServerPreRequestResult} from 'dns2ts';
import type {RemoteInfo} from 'dgram';

class TaggingHook implements ServerPreRequest<RemoteInfo> {
  async process(data: Buffer, client: RemoteInfo): Promise<ServerPreRequestResult<RemoteInfo>> {
    metrics.incr('dns.requests', {src: client.address});
    return {data: data};   // unchanged buffer
  }
}
```

## Errors

Two channels:

- `requestError` — emitted when a parser, handler, or transport raises.
  The argument is an `Error`.
- `error` — emitted by the combined `DnsServer` with a second `transport`
  argument (`'udp' | 'tcp' | 'tls' | 'doh'`) so you know which protocol is
  unhealthy.

```ts
server.on('requestError', (err) => log.warn(err));
server.on('error', (err, transport) => log.error({transport: transport}, err));
```

A malformed UDP datagram or invalid TCP frame produces a `requestError`; the
listener stays up and continues to accept further traffic.

## Lifecycle

```ts
const addresses = await server.listen({udp: 0, tcp: 0});  // port 0 → ephemeral
// … serve traffic …
await server.close();                                     // resolves once every transport is closed
```

`server.close()` returns a promise that resolves after every constituent
server has emitted `close`. Pending in-flight TCP/TLS connections are allowed
to finish their current frame before the listener stops accepting new ones.

## Standalone protocol servers

If you only want one transport, the protocol-specific servers expose the
same API at a lower level — useful for tests or when you have unusual
listen-side requirements.

```ts
import {TLSServer, Packet} from 'dns2ts';

const tls = new TLSServer({
  tls: {options: {cert, key}},
});

tls.on('request', (req, send) => send(Packet.createResponseFromRequest(req)));
tls.listen(853);
```

`TCPServer.listen(...)` accepts the full `net.Server.listen` signature, so
backlog and host overrides work as expected. `UDPServer.listen(port, addr?)`
returns a promise that resolves on `bind`.