# DNS UPDATE — dynamic updates (RFC 2136)

DNS UPDATE turns a DNS server into a writable database. Instead of
editing a zone file and reloading, an authorized client sends a UPDATE
message containing a list of "add this", "delete this" actions —
optionally guarded by *prerequisite* tests — and the server applies the
changes atomically.

UPDATE is what `nsupdate` speaks, what Active Directory uses for
auto-registering host records, and the protocol behind certbot's
`dns-rfc2136` ACME challenge plugin.

## Wire format at a glance

UPDATE reuses the standard DNS message layout but renames the four
sections (RFC 2136 §2.3):

| Section in `Packet`   | UPDATE meaning   | What lives there                |
| --------------------- | ---------------- | ------------------------------- |
| `questions`           | **Zone**         | exactly one `(zone, SOA, IN)`   |
| `answers`             | **Prerequisite** | tests that must pass            |
| `authorities`         | **Update**       | the actual changes              |
| `additionals`         | unchanged        | TSIG / EDNS                     |

The opcode field is `UPDATE (5)` — `PacketOpcode.UPDATE` in dns2ts.

## Client side — `UpdateBuilder` + `UpdateClient`

`UpdateBuilder` is a small fluent API for assembling the message. Five
prerequisite kinds and four update kinds map to one method each:

```ts
import {
  UpdateBuilder, UpdateClient, PacketResource, PacketClass, PacketTypes, A,
} from 'dns2ts';

const builder = new UpdateBuilder('example.com')
  // Prerequisites — RFC 2136 §2.4
  .requireNameInUse('www.example.com')
  .requireRRsetExists('www.example.com', PacketTypes.A)
  // Updates — RFC 2136 §2.5
  .deleteRRset('mx.example.com', PacketTypes.MX)
  .add(new PacketResource('mx.example.com',
                          new A('192.0.2.10'),
                          PacketClass.IN, 300));

const send = UpdateClient.request({dns: 'ns.example.com', port: 53});
const response = await send(builder);

console.log(response.header.rcode);     // 0 = NOERROR, see UpdateRcode
```

The client function accepts a builder (the common path), a fully-formed
`Packet`, or a raw `Buffer` — the Buffer overload preserves the exact
wire bytes, which matters for TSIG-signed messages because the MAC is
bound to specific bytes (re-encoding may pick different name compression).

### Prerequisite forms

| Builder method                                      | Meaning (RFC 2136 §2.4)                       |
| --------------------------------------------------- | --------------------------------------------- |
| `requireNameInUse(name)`                            | At least one RR exists at `name`              |
| `requireNameNotInUse(name)`                         | No RR exists at `name`                        |
| `requireRRsetExists(name, type)`                    | Some RR of `type` exists at `name`            |
| `requireRRsetAbsent(name, type)`                    | No RR of `type` exists at `name`              |
| `requireRRsetMatches(record)`                       | The RRset at `(name, record.type)` matches the supplied record exactly |

### Update forms

| Builder method                  | Meaning (RFC 2136 §2.5)                      |
| ------------------------------- | -------------------------------------------- |
| `add(record)`                   | Add the RR (or refresh TTL if it exists)     |
| `deleteName(name)`              | Delete every RR at `name`                    |
| `deleteRRset(name, type)`       | Delete the entire RRset at `(name, type)`    |
| `deleteRR(record)`              | Delete one specific RR (matches RDATA)       |

### Transports

UDP by default, TCP and TLS available. Pick TCP/TLS when the message is
larger than ~512 bytes (multiple updates) or when your environment
forbids UDP:

```ts
import {ClientOptionsProtocol} from 'dns2ts';

const send = UpdateClient.request({
  dns: 'ns.example.com',
  port: 853,
  protocol: ClientOptionsProtocol.tls,
});
```

The reply is a small DNS message echoing the opcode and carrying the
RCODE — your code only needs to look at `response.header.rcode` and the
matching `UpdateRcode` enum value.

## Server side

UPDATE messages don't need a dedicated server class. Dispatch on
`request.header.opcode` in your existing handler, parse the message, and
apply it to whatever storage backend you have:

```ts
import {DnsServer, Packet, PacketOpcode, Update, UpdateRcode, Zone} from 'dns2ts';

const zone = Zone.fromZoneFile(/* … */);

const server = new DnsServer({
  udp: true,
  tcp: true,
  handle: (request, send) => {
    if (request.header.opcode !== PacketOpcode.UPDATE) {
      // … normal QUERY handling …
      return;
    }

    if (!isAuthorized(request /* IP + TSIG */)) {
      send(Update.buildResponse(request, UpdateRcode.REFUSED));
      return;
    }

    const msg = Update.parse(request);
    const rcode = Update.applyToZone(zone, msg);
    send(Update.buildResponse(request, rcode));
  },
});
```

`Update.applyToZone(zone, msg)` evaluates every prerequisite first; if
any fails, it returns the matching RCODE without touching `zone.records`.
Otherwise it walks the update list in order and mutates `zone.records`
in place. The five RCODEs you'll typically see:

| `UpdateRcode` | When                                                     |
| ------------- | -------------------------------------------------------- |
| `NOERROR` (0) | All prerequisites passed; updates applied                |
| `NXDOMAIN` (3)| `requireNameInUse` failed                                |
| `NOTZONE` (10)| Zone in the question doesn't match this server's zone    |
| `YXDOMAIN` (6)| `requireNameNotInUse` failed (name is present)           |
| `YXRRSET` (7) | `requireRRsetAbsent` failed (RRset is present)           |
| `NXRRSET` (8) | `requireRRsetExists` or `requireRRsetMatches` failed     |

### Inspecting / classifying records by hand

If you want a custom apply path (for example, you persist to a database
rather than in-memory `Zone`), use the classifier helpers directly:

```ts
import {Update} from 'dns2ts';

const msg = Update.parse(request);

for (const pre of msg.prerequisites) {
  const check = Update.classifyPrerequisite(pre);
  // check.kind: 'nameInUse' | 'nameNotInUse' | 'rrsetExists' |
  //             'rrsetAbsent' | 'rrsetMatchesExactly'
}

for (const upd of msg.updates) {
  const action = Update.classifyUpdate(upd);
  switch (action.kind) {
    case 'add':         /* INSERT INTO rr (...) VALUES (...) */; break;
    case 'deleteName':  /* DELETE FROM rr WHERE name=$1 */; break;
    case 'deleteRRset': /* DELETE FROM rr WHERE name=$1 AND type=$2 */; break;
    case 'deleteRR':    /* DELETE FROM rr WHERE name=$1 AND type=$2 AND rdata=$3 */; break;
  }
}
```

Both classifiers return discriminated unions, so TypeScript narrows the
fields per case automatically.

## Authentication is mandatory

UPDATE without auth lets anyone reachable on port 53 rewrite your zone.
The two production-grade options:

- **TSIG** (RFC 8945) — a shared HMAC key on both sides. The standard
  setup; what `nsupdate -k`, `dnspython`, and certbot use. See the
  [TSIG guide](tsig.md).
- **DoT with mutual TLS** — combine `UpdateClient` with
  `ClientOptionsProtocol.tls` and run the server with
  `tls.options.requestCert: true` plus a CA pin.

A typical handler layers both. The 4th arg of the `request` event (and
`ServerRequestHandler`) carries the post-`preRequest` raw wire bytes —
exactly what `Packet.parse` saw — so TSIG verification can operate on
them directly without re-encoding. The `send` callback also accepts a
`Buffer`, so a `Tsig.sign(...).buffer` reply ships byte-for-byte:

```ts
handle: async (request, send, client, raw) => {
  if (request.header.opcode !== PacketOpcode.UPDATE) { /* … */ return; }

  // 1. IP allow-list (cheap first-line filter)
  const sock = client as net.Socket;
  if (!ALLOWED_IPS.has(sock.remoteAddress!)) {
    send(Update.buildResponse(request, UpdateRcode.REFUSED));
    return;
  }

  // 2. TSIG (the actual security boundary)
  const tsigCheck = Tsig.verify(request, raw, key);
  if (!tsigCheck.valid) {
    send(Tsig.sign(Update.buildResponse(request, UpdateRcode.NOTAUTH), key,
                   {error: TsigError.BADSIG}).buffer);
    return;
  }

  // 3. Apply, then sign the reply (chained from the request MAC)
  const rcode = Update.applyToZone(zone, Update.parse(request));
  const reply = Update.buildResponse(request, rcode);
  send(Tsig.sign(reply, key, {requestMac: tsigCheck.tsig!.mac}).buffer);
};
```

On the client side, ship the signed bytes via the `Buffer` overload of
`UpdateClient.request(...)`:

```ts
const send = UpdateClient.request({dns: '127.0.0.1', port: 53});
const signed = Tsig.sign(builder.toPacket(), key);
const response = await send(signed.buffer);
```

## A complete worked example

```ts
import {DnsServer, Packet, PacketOpcode, PacketResource, PacketClass, PacketTypes,
        A, Update, UpdateBuilder, UpdateClient, UpdateRcode, Zone} from 'dns2ts';

const zone = Zone.fromZoneFile(`
$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 admin (1 7200 3600 1209600 3600)
@ IN NS  ns1
www IN A 192.0.2.1
`);

// Server — dispatches on opcode.
const server = new DnsServer({
  udp: true, tcp: true,
  handle: (request, send) => {
    if (request.header.opcode === PacketOpcode.UPDATE) {
      const rcode = Update.applyToZone(zone, Update.parse(request));
      send(Update.buildResponse(request, rcode));
      return;
    }

    // … standard QUERY path …
  },
});
const {udp} = await server.listen();

// Client — replace www's A record with a new address, but only if the
// old one is still there (race-free).
const builder = new UpdateBuilder('example.com')
  .requireRRsetMatches(new PacketResource('www.example.com',
                                          new A('192.0.2.1'),
                                          PacketClass.IN, 0))
  .deleteRRset('www.example.com', PacketTypes.A)
  .add(new PacketResource('www.example.com',
                          new A('192.0.2.99'),
                          PacketClass.IN, 60));

const send = UpdateClient.request({dns: '127.0.0.1', port: udp!.port});
const response = await send(builder);
console.log(UpdateRcode[response.header.rcode]);   // "NOERROR"
```

## What's not implemented

- **Persistence**. `Update.applyToZone` mutates an in-memory `Zone`. For
  a real authoritative server, you'll want to atomically persist to disk
  or a database after each successful UPDATE.
- **Zone file rewrites** triggered by UPDATE. dns2ts has no zone-file
  *writer* yet, so an UPDATE-driven server can't dump the new state back
  to BIND-style text. Roundtripping through wire format works fine; the
  text form is one-way for now.
- **Zone change journaling for IXFR**. If you serve IXFR
  ([guide](ixfr.md)) and accept UPDATE, you'll want to record the
  add/delete sets as `ZoneChangeSet` entries so secondaries can fetch
  diffs instead of full transfers. dns2ts doesn't do this for you yet.

## Related

- [Zone files](zone-files.md) — load a zone into a `Zone`, then accept
  UPDATEs against it.
- [AXFR](axfr.md) / [IXFR](ixfr.md) — how secondaries fetch the new state
  after an UPDATE-driven change.
- [NOTIFY](notify.md) — push the "fresh data is ready" hint to
  secondaries after applying UPDATEs.
- [TSIG](tsig.md) — the right authentication for UPDATE.