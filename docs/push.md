# DNS Push Notifications (RFC 8765)

DNS Push Notifications let a client subscribe to changes for a
particular `(name, type, class)` and receive server-initiated PUSH
messages whenever the underlying RRset changes — instead of polling
on TTL. It's built on top of **DSO** (DNS Stateful Operations,
RFC 8490): a long-lived TLS connection (port 853, same as DoT) over
which the two ends exchange `opcode = 6` messages whose body is a
sequence of TLVs.

This package ships three layers:

- **`Lib/Dso`** — the RFC 8490 wire format. TLV encode/decode for
  every defined type (KEEPALIVE / RETRY_DELAY / ENCRYPTION_PADDING /
  SUBSCRIBE / PUSH / UNSUBSCRIBE / RECONFIRM) plus `UnknownDsoTlv`
  for round-tripping anything else.
- **`Client/PushClient`** — a `PushClient` that opens a TLS
  connection, sends SUBSCRIBE, dispatches incoming PUSH messages to
  the matching `PushSubscription` handle.
- **`Server/PushServer`** — a `PushServer` that accepts DSO
  connections, tracks subscriptions, and fans out PUSH messages via
  `notify()`.

## Quick start — subscribing as a client

```ts
import {PushClient, PacketTypes, PacketClass} from 'dns2ts';

const client = new PushClient({
  host: 'dns-push.example.net',
  port: 853,
});

const sub = await client.subscribe('app.example.com', PacketTypes.A);

sub.on('push', (records) => {
  for (const r of records) {
    if (r.ttl === 0xFFFFFFFF) {
      console.log('RRset deleted:', r.name);
    } else {
      console.log('new record:', r.name, r.packetType);
    }
  }
});

// later:
await sub.unsubscribe();
await client.close();
```

A single `PushClient` connection multiplexes any number of
subscriptions. Subscriptions are routed to events by matching
`(name, type, class)`; `qtype = 255` (ANY) on a subscription matches
every record type for the given name.

## Quick start — running a push server

```ts
import {PushServer, PacketResource, PacketClass, PacketTypes} from 'dns2ts';
import {A} from 'dns2ts';
import fs from 'fs';

const server = new PushServer({
  tls: {
    cert: fs.readFileSync('server.crt'),
    key:  fs.readFileSync('server.key'),
  },
});

await server.listen(853, '0.0.0.0');

// Notify every subscriber to 'app.example.com A' that the record changed:
server.notify([
  new PacketResource('app.example.com', new A('192.0.2.5'), PacketClass.IN, 60),
]);

// On graceful shutdown:
await server.close();
```

Events:

| Event             | Payload                                          | When                                                                    |
| ----------------- | ------------------------------------------------ | ----------------------------------------------------------------------- |
| `'connection'`    | `(session: PushSession)`                         | New TLS connection accepted.                                            |
| `'subscribe'`     | `(tlv: SubscribeTlv, session: PushSession)`      | After server has acknowledged a SUBSCRIBE with RCODE 0.                 |
| `'unsubscribe'`   | `(tlv: UnsubscribeTlv, session: PushSession)`    | Client sent UNSUBSCRIBE — already removed from the session's registry.  |
| `'reconfirm'`     | `(tlv: ReconfirmTlv, session: PushSession)`      | Client asks the server to re-verify a cached record. App policy.        |
| `'error'`         | `(err: Error)`                                   | Frame parse errors and other internal failures.                         |

## What's in the wire

Every DSO message has the standard 12-byte DNS header with
`opcode = 6` and all four section counts forced to 0. The body is a
flat sequence of TLVs:

```
+----+----+----+----+----+----+----+----+
|       16-bit TYPE       | 16-bit LEN  |
+----+----+----+----+----+----+----+----+
|              LEN bytes of DATA        |
+----+----+----+...+----+----+----+----+
```

The first TLV in a message is the **primary** TLV — it tells the
receiver what the message means. Subsequent TLVs are **additional**
TLVs (encryption padding, modifier metadata). RFC 8490 §4 forbids
DNS name-compression pointers across TLV boundaries; the encoder in
this package builds each TLV against a fresh `BufferWriter` so
pointers can never leak.

For exact wire shapes, see the encode/decode methods on each TLV
class in `Lib/Dso.ts`.

## What's not implemented yet

- **Periodic KEEPALIVE heartbeats from the client.** The initial
  KEEPALIVE TLV is sent during connection setup to advertise the
  client's preferred window, but the client doesn't yet schedule
  periodic heartbeats. Long-lived idle connections will be closed by
  servers enforcing their inactivity timeout — wrap the client with
  a reconnect loop if your sessions outlast it.
- **Automatic reconnect on `RETRY_DELAY`.** The server can ask
  clients to back off via the RETRY_DELAY TLV; the current client
  parses it but doesn't act on it.
- **Server-side RECONFIRM policy.** Clients can send RECONFIRM but
  the server only emits a `'reconfirm'` event — the app decides
  whether to re-push, refuse, or silently ignore.
- **Subscription deduplication on the server.** A subscription
  registry indexed by `(name, type, class)` would beat the current
  walk-every-session fan-out at high subscriber counts; the current
  implementation is fine for "tens to hundreds of subscribers" but
  not for "tens of thousands". Swap `PushServer._sessions` for an
  index when that hurts.