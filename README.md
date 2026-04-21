
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
- DNS over UDP, TCP, TLS, and HTTPS (DoH)
- 20 record types: A, AAAA, MX, NS, CNAME, PTR, SRV, SOA, TXT, SPF, CAA, EDNS (with ECS), DNSKEY, DS, NAPTR, NSEC, NSEC3, RRSIG, SSHFP, TLSA
- PROXY protocol v1 and v2 support (UDP per-datagram, TCP per-connection) for transparent load-balancer deployments

<hr>

### Features

+ Server and Client
+ Lot of Type Supported
+ Extremely lightweight
+ DNS over UDP, TCP, TLS, HTTPS Supported

### Installation

```bash
$ npm install git+https://github.com/stefanwerfling/node-dns.git#ts
```

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
+ [RFC-4034 - Resource Records for the DNS Security Extensions (DNSSEC)](https://tools.ietf.org/html/rfc4034)
+ [RFC-6891 - Extension Mechanisms for DNS (EDNS(0))](https://tools.ietf.org/html/rfc6891)
+ [RFC-7766 - DNS Transport over TCP - Implementation Requirements](https://tools.ietf.org/html/rfc7766)
+ [RFC-7871 - Client Subnet in DNS Queries](https://tools.ietf.org/html/rfc7871)
+ [RFC-8484 - DNS Queries over HTTPS (DoH)](https://tools.ietf.org/html/rfc8484)

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