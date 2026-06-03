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

## Long-lived sessions

A real-world push session typically outlives any single TCP
connection. Two ingredients keep it healthy:

### Periodic KEEPALIVE heartbeats

After the initial KEEPALIVE TLV (which advertises the client's
preferred inactivity/keepalive window), the client schedules a
heartbeat every `keepaliveMs` of socket inactivity. Each outbound
message — including PUSH responses, SUBSCRIBE, UNSUBSCRIBE,
RECONFIRM — resets the timer, so an active session never wastes a
heartbeat. Pass `keepaliveMs: 0` to disable both the initial KEEPALIVE
and the periodic refresh.

### Auto-reconnect with `RETRY_DELAY`

Opt in with `autoReconnect: true`. When the server closes the session
(by sending `RETRY_DELAY` + closing, or just closing), the client:

1. Waits for either the server's most recent `RETRY_DELAY` value or
   `reconnectDelayMs` (default 1000ms).
2. Re-opens a fresh TLS connection.
3. Re-issues SUBSCRIBE for every active subscription — the same
   `PushSubscription` instances continue receiving `'push'` events,
   their `messageId` is re-keyed under the hood.

Events to watch:

| Client event       | Payload                | When                                                              |
| ------------------ | ---------------------- | ----------------------------------------------------------------- |
| `'retryDelay'`     | `(ms: number)`         | Server sent a RETRY_DELAY TLV — observable even without auto-reconnect.   |
| `'reconnect'`      | `()`                   | After all active subscriptions were re-issued successfully.       |
| `'reconnectFailed'`| `(err: Error)`         | Hit `maxReconnectAttempts` (default `Infinity`) — subscriptions are torn down. |
| `'error'`          | `(err: Error)`         | Individual reconnect attempt failed. Subsequent attempts are still queued unless the cap is reached. |

```ts
const client = new PushClient({
  host: 'dns-push.example.net',
  autoReconnect: true,
  reconnectDelayMs: 2_000,         // fallback when no RETRY_DELAY
  maxReconnectAttempts: 5,         // give up after 5 consecutive fails
});

client.on('reconnect', () => console.log('back online'));
client.on('reconnectFailed', (err) => alert('giving up: ' + err.message));
```

## RECONFIRM

When a client suspects a cached PUSH-delivered record is no longer
correct (e.g. an A-record's target host is unreachable), it can ask
the server to re-verify via `client.reconfirm(name, type, class,
rdata)`. RFC 8765 §6.5: the message is unacknowledged — the server's
follow-up (re-push the same RRset, push a corrected one, or do
nothing) shows up as a future `'push'` event on the relevant
subscription.

```ts
import {Buffer} from 'node:buffer';

await client.reconfirm(
  'app.example.com', PacketTypes.A, PacketClass.IN,
  Buffer.from([192, 0, 2, 5])      // the rdata you want re-checked
);
```

## Server-side load shedding via `RETRY_DELAY`

`PushSession.sendRetryDelay(ms, closeAfter?)` ships a unilateral
RETRY_DELAY TLV. Pass `closeAfter: true` to also tear down the
session once the bytes have flushed — RFC 8490 §7.2: the canonical
pattern for "I'm too busy, come back later".

```ts
server.on('connection', (session) => {
  if (currentLoad > threshold) {
    session.sendRetryDelay(60_000, true);  // 1 minute, then close
  }
});
```

## What's not implemented yet

- **Server-side RECONFIRM policy.** Clients can send RECONFIRM but
  the server only emits a `'reconfirm'` event — the app decides
  whether to re-push, refuse, or silently ignore.
- **Subscription deduplication on the server.** A subscription
  registry indexed by `(name, type, class)` would beat the current
  walk-every-session fan-out at high subscriber counts; the current
  implementation is fine for "tens to hundreds of subscribers" but
  not for "tens of thousands". Swap `PushServer._sessions` for an
  index when that hurts.