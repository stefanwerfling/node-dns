# Reverse proxy

You can run a dns2ts server directly on `:53` and `:853`/`:443`, but in most
production deployments you'll want a reverse proxy (nginx, HAProxy, or Envoy)
in front. The proxy handles things dns2ts doesn't:

- **TLS termination** for DoT/DoH on a battle-tested stack
- **Cert reload** (Let's Encrypt rotation) without restarting Node
- **Rate limiting** at the network edge
- **Health checks and failover** between multiple Node backends
- **PROXY-protocol IP transparency** so dns2ts still sees the real client
- **Privileged port binding** without granting Node `CAP_NET_BIND_SERVICE`

This guide covers three popular proxies. Pick whichever your team already
runs; the dns2ts side is identical.

## Three deployment patterns

Before configs, the three patterns to keep clear:

1. **Pass-through (TLS terminated at backend)** — proxy just forwards
   bytes; dns2ts handles TLS. Use when you want end-to-end TLS for client →
   backend, or when the proxy can't speak DNS-aware protocols (it doesn't
   need to).

2. **Termination (TLS terminated at proxy)** — proxy decrypts DoT/DoH and
   forwards plain DNS over TCP/UDP to dns2ts. Most common for DoH because
   it lets you use a real HTTP frontend with HTTP/2.

3. **PROXY-protocol layered** — orthogonal to the above. The proxy
   prepends a PROXY-protocol header so dns2ts sees the real client IP.

Pick (1 or 2) **and** decide on (3). Most setups should enable PROXY-
protocol unless your handler doesn't care about source IPs (e.g. it only
serves a static zone with no per-client behavior).

## nginx

nginx covers all three patterns. UDP/TCP DNS lives in the `stream` module
(L4); DoH lives in the `http` module (L7).

### Pattern 1 — TLS pass-through to a DoT backend

dns2ts terminates TLS itself; nginx is just an L4 forwarder with optional
PROXY-protocol injection.

```nginx
stream {
    upstream dns_dot_backend {
        server 10.0.0.10:8853;          # dns2ts TLSServer listening here
    }

    server {
        listen 853;                     # DoT
        proxy_pass dns_dot_backend;
        proxy_protocol on;              # send PROXY v2 preamble
        proxy_timeout 60s;
        proxy_connect_timeout 5s;
    }
}
```

Backend (dns2ts):

```ts
import {DnsServer, ProxyProtocolV2Tcp} from 'dns2ts';

new DnsServer({
  tls: {
    options: {cert, key},
    preConnection: new ProxyProtocolV2Tcp(),     // strip nginx's preamble
  },
  handle,
}).listen({tls: 8853});
```

### Pattern 2 — TLS termination at nginx, plain DNS to backend

nginx decrypts; backend speaks plain TCP DNS.

```nginx
stream {
    upstream dns_tcp_backend {
        server 10.0.0.10:5353;
    }

    server {
        listen 853 ssl;                 # DoT, terminated here
        ssl_certificate     /etc/ssl/dns.example.com.fullchain.pem;
        ssl_certificate_key /etc/ssl/dns.example.com.key.pem;
        ssl_protocols       TLSv1.3 TLSv1.2;
        ssl_session_timeout 1h;

        proxy_pass dns_tcp_backend;
        proxy_protocol on;
        proxy_timeout 60s;
    }
}
```

Backend:

```ts
new DnsServer({
  tcp: { preConnection: new ProxyProtocolV2Tcp() },
  handle,
}).listen({tcp: 5353});
```

### UDP DNS through nginx

nginx's `stream` module supports UDP. Each datagram becomes a "session"
that lives `proxy_responses` round-trips long.

```nginx
stream {
    upstream dns_udp_backend {
        server 10.0.0.10:5353;
    }

    server {
        listen 53 udp;
        proxy_pass dns_udp_backend;
        proxy_protocol on;             # nginx supports v2 for UDP since 1.13.11
        proxy_timeout 5s;
        proxy_responses 1;             # exactly one reply expected
    }
}
```

Backend:

```ts
new DnsServer({
  udp: { preRequest: new ProxyProtocolV2() },
  handle,
}).listen({udp: 5353});
```

> **Caveat**: nginx's UDP `proxy_protocol` is v2-only (no v1). It also
> implies `transport = DGRAM` in the v2 header — make sure your backend's
> hook reads the family/transport correctly (dns2ts already does).

### DoH through nginx (HTTP/2 termination)

DoH lives at L7 — nginx terminates TLS and HTTP/2, then sends plain HTTP
to the backend.

```nginx
http {
    upstream doh_backend {
        server 127.0.0.1:5380;
        keepalive 16;
    }

    server {
        listen              443 ssl http2;
        server_name         dns.example.com;
        ssl_certificate     /etc/ssl/dns.example.com.fullchain.pem;
        ssl_certificate_key /etc/ssl/dns.example.com.key.pem;

        location /dns-query {
            proxy_pass         http://doh_backend;
            proxy_http_version 1.1;
            proxy_set_header   Host              $host;
            proxy_set_header   X-Real-IP         $remote_addr;
            proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto $scheme;

            client_max_body_size 64k;        # plenty for any DoH POST body
            proxy_buffering      off;        # tiny replies, no buffering needed
        }
    }
}
```

Backend:

```ts
new DnsServer({
  doh: { /* ssl: false — nginx already terminated */ },
  handle: (request, send, client) => {
    const req = client as http.IncomingMessage;
    const realIp = req.headers['x-real-ip'] ?? req.socket.remoteAddress;
    // …
  },
}).listen({doh: 5380});
```

For DoH the proxy hands you the real client IP via headers, not via PROXY
protocol — `X-Forwarded-For` / `X-Real-IP` are the convention. Your DoH
handler reads them off the `IncomingMessage`.

### Putting nginx and dns2ts on the same box (DoH + DoT + plain)

```nginx
stream {
    upstream dns_tcp { server 127.0.0.1:5353; }
    upstream dns_udp { server 127.0.0.1:5353; }
    upstream dns_dot { server 127.0.0.1:5353; }     # nginx terminates TLS

    server {                          # plain TCP DNS
        listen 53;
        proxy_pass dns_tcp;
        proxy_protocol on;
    }
    server {                          # plain UDP DNS
        listen 53 udp;
        proxy_pass dns_udp;
        proxy_protocol on;
        proxy_responses 1;
    }
    server {                          # DoT
        listen 853 ssl;
        ssl_certificate     /etc/ssl/dns.crt;
        ssl_certificate_key /etc/ssl/dns.key;
        proxy_pass dns_dot;
        proxy_protocol on;
    }
}

http {
    upstream doh { server 127.0.0.1:5380; }
    server {
        listen 443 ssl http2;
        ssl_certificate     /etc/ssl/dns.crt;
        ssl_certificate_key /etc/ssl/dns.key;
        location /dns-query {
            proxy_pass http://doh;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }
}
```

Single dns2ts process listens on `5353` (UDP+TCP) and `5380` (DoH-plain):

```ts
new DnsServer({
  udp: { preRequest:    new ProxyProtocolV2() },
  tcp: { preConnection: new ProxyProtocolV2Tcp() },
  doh: { /* ssl: false */ },
  handle,
}).listen({udp: 5353, tcp: 5353, doh: 5380});
```

## HAProxy

HAProxy is built around proxy-protocol from day one and has excellent
DNS support. The terminology: `mode tcp` for any L4 traffic (including
DoT pass-through and DNS over TCP), `mode http` for DoH.

### TCP/DoT with PROXY v2

```haproxy
defaults
    timeout connect 5s
    timeout client  60s
    timeout server  60s

frontend dns_tcp
    bind *:53
    mode tcp
    default_backend dns_tcp_backend

backend dns_tcp_backend
    mode tcp
    server dns2ts 10.0.0.10:5353 send-proxy-v2 check

frontend dot
    bind *:853 ssl crt /etc/ssl/dns.example.com.pem
    mode tcp
    default_backend dns_tcp_backend          # plain DNS to backend after TLS termination
```

`send-proxy-v2` enables PROXY v2 toward the backend. Add `send-proxy-v2-ssl`
if you want HAProxy to also propagate the TLS info as a v2 TLV (rarely
needed for DNS).

### UDP DNS with HAProxy

HAProxy 2.4+ supports UDP via the `quic` and `dgram` listeners
(`bind quic@*:853` for DoQ, `bind dgram@*:53` for plain DNS UDP). Older
HAProxy versions don't speak UDP at all — fall back to nginx for UDP if
you're on an older HAProxy.

```haproxy
frontend dns_udp
    bind dgram@*:53 transparent
    mode dgram
    default_backend dns_udp_backend

backend dns_udp_backend
    mode dgram
    server dns2ts dgram@10.0.0.10:5353 send-proxy-v2
```

### DoH with HAProxy

```haproxy
frontend doh
    bind *:443 ssl crt /etc/ssl/dns.example.com.pem alpn h2,http/1.1
    mode http
    http-request set-header X-Real-IP %[src]
    default_backend doh_backend

backend doh_backend
    mode http
    server dns2ts 10.0.0.10:5380 check
```

dns2ts side is the same as for nginx-DoH: read `X-Real-IP` from the
`IncomingMessage`.

### Health checks

HAProxy can drive backend `check` with a synthetic DNS query — useful for
detecting a stuck dns2ts process. The simplest is a TCP-level
`check connect`:

```haproxy
backend dns_tcp_backend
    mode tcp
    option tcp-check
    tcp-check connect
    server dns2ts 10.0.0.10:5353 send-proxy-v2 check
```

For real DNS-aware probing, run a side-car DNS client and feed HAProxy
external state (`socket admin` or `agent-check`).

## Envoy

Envoy 1.18+ has first-class UDP support; earlier versions don't. The L4
listener type is `tcp_proxy`/`udp_proxy`, and PROXY protocol is a
filter you attach to the cluster.

### TCP / DoT pass-through with PROXY v2

```yaml
static_resources:
  listeners:
    - name: dns_tcp
      address:
        socket_address: { address: 0.0.0.0, port_value: 53 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: dns_tcp
                cluster: dns_tcp_backend

  clusters:
    - name: dns_tcp_backend
      connect_timeout: 5s
      type: STATIC
      load_assignment:
        cluster_name: dns_tcp_backend
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: 10.0.0.10, port_value: 5353 }
      transport_socket:
        name: envoy.transport_sockets.upstream_proxy_protocol
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.proxy_protocol.v3.ProxyProtocolUpstreamTransport
          config: { version: V2 }
          transport_socket:
            name: envoy.transport_sockets.raw_buffer
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.raw_buffer.v3.RawBuffer
```

The `proxy_protocol` upstream transport socket prepends a v2 header on
each outbound connection to the backend.

### UDP DNS through Envoy

```yaml
listeners:
  - name: dns_udp
    address:
      socket_address: { protocol: UDP, address: 0.0.0.0, port_value: 53 }
    udp_listener_config: {}
    listener_filters:
      - name: envoy.filters.udp_listener.udp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.udp.udp_proxy.v3.UdpProxyConfig
          stat_prefix: dns_udp
          matcher:
            on_no_match:
              action:
                name: route
                typed_config:
                  "@type": type.googleapis.com/envoy.extensions.filters.udp.udp_proxy.v3.Route
                  cluster: dns_udp_backend
```

Envoy's UDP proxy doesn't currently emit PROXY protocol on UDP — if you
need source-IP transparency through Envoy on UDP, your options are
HAProxy/nginx in front of Envoy, or use Envoy's own header-injection on
the L7 path (DoH).

### DoH at L7

Envoy's HTTP filters and `http_connection_manager` give you a normal HTTP
listener; route `/dns-query` to your dns2ts DoH backend. Add the
`envoy.filters.http.router` filter and pass through the standard
`x-forwarded-for` headers.

## PROXY protocol — protocol matrix

| Path                              | Recommended PROXY version        | dns2ts hook                    |
| --------------------------------- | -------------------------------- | ------------------------------ |
| nginx → dns2ts plain TCP          | v2 (`proxy_protocol on`)         | `ProxyProtocolV2Tcp` on `tcp`  |
| nginx → dns2ts plain UDP          | v2 (UDP, nginx ≥ 1.13.11)        | `ProxyProtocolV2` on `udp`     |
| nginx-TLS-terminated → dns2ts TCP | v2                               | `ProxyProtocolV2Tcp` on `tcp`  |
| nginx-passthrough → dns2ts TLS    | v2                               | `ProxyProtocolV2Tcp` on `tls`  |
| HAProxy → dns2ts TCP              | v2 (`send-proxy-v2`)             | `ProxyProtocolV2Tcp` on `tcp`  |
| HAProxy → dns2ts UDP              | v2 (HAProxy ≥ 2.4)               | `ProxyProtocolV2` on `udp`     |
| Envoy → dns2ts TCP                | v2 (transport socket)            | `ProxyProtocolV2Tcp` on `tcp`  |
| nginx-DoH frontend                | not used; X-Real-IP / XFF instead | read headers from `IncomingMessage` |

Use v1 only if you absolutely have to (some old proxies). The dns2ts
`ProxyProtocolV1` and `ProxyProtocolV1Tcp` classes parse it identically.

## Troubleshooting

### First DNS query just hangs

Usually the proxy is sending a different PROXY version than the backend
expects (or none at all). Check both ends:

- Proxy: in nginx `proxy_protocol on;`, in HAProxy `send-proxy-v2`.
- Backend: did you attach `ProxyProtocolV2Tcp` to the right block (`tcp`
  vs `tls`)?

Run `nc -l 5353 | xxd` on the backend host (with the real backend stopped)
to see what arrives. v2 starts with `0d 0a 0d 0a 00 0d 0a 51 55 49 54 0a`,
v1 starts with the ASCII `PROXY `.

### Real client IP is the proxy's IP

Either no PROXY protocol is configured, or the hook is on the wrong
listener. With nginx-DoH (HTTP path) PROXY protocol is the wrong tool —
read `X-Real-IP` instead.

### "Empty UDP responses" from upstream proxy

nginx UDP `proxy_responses 1` requires *exactly one* response. AXFR-style
multi-message replies don't apply (AXFR is TCP), but if you do something
non-standard like multi-UDP, raise `proxy_responses` accordingly.

### Backend gets `requestError: malformed PROXY` on every connection

The backend is wired up for v2 but receiving v1 (or vice-versa). The
distinguishing byte sequences are very different, so even a single mistake
in the proxy config shows up immediately.

### TLS handshake fails through nginx-TLS-passthrough

In pass-through mode, nginx must not terminate TLS — make sure the listener
is `listen 853;` (no `ssl` keyword) and `ssl_preread on;` is set if you
want SNI-based routing:

```nginx
stream {
    map $ssl_preread_server_name $upstream {
        dns.example.com         dns_dot_backend;
        default                 dns_dot_default;
    }
    server {
        listen 853;
        ssl_preread on;
        proxy_pass $upstream;
        proxy_protocol on;
    }
}
```

### Source-port preservation

By default the proxy creates new outbound connections with its own source
ports. PROXY protocol carries the *original* client port in its header, so
your handler still sees the real value. If you also need the OS-level
ephemeral port preserved (rare — usually only for source-NAT scenarios),
use kernel-level transparent proxying (nginx `transparent`, HAProxy
`transparent`) — but that's outside dns2ts's concern.

## Checklist for a new deployment

1. Decide pass-through vs termination per protocol (UDP/TCP/DoT/DoH).
2. Pick a PROXY version (v2 unless legacy).
3. Configure the proxy with the matching directive
   (`proxy_protocol on;` / `send-proxy-v2` / Envoy upstream transport).
4. Attach the matching dns2ts hook to the right `ServerOptions` block.
5. Verify with a query from outside; the handler should log the real
   client IP.
6. Add a synthetic DNS health check on the proxy.
7. Layer rate limiting on the proxy, **not** in dns2ts — that's the
   proxy's job and it does it better.