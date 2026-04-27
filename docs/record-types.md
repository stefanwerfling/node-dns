# Record types

dns2ts implements 23 RR types as classes that extend `PacketType`. Each one
has the same lifecycle: a constructor for outbound records, a static
`decode(reader, length)` for inbound parsing, and an instance `encode(...)`
that writes the wire format. You normally only interact with the constructor.

Unsupported types are still parsed: the registry returns an
`UnknownPacketType` instance with the raw RDATA bytes preserved, so an
unknown RR survives a roundtrip through the library.

## Quick reference

| Type     | Code   | Class             | RDATA fields                                       |
| -------- | -----: | ----------------- | -------------------------------------------------- |
| A        | 1      | `A`               | `address: string` (IPv4 dotted)                    |
| NS       | 2      | `NS`              | `ns: string` (FQDN)                                |
| CNAME    | 5      | `CNAME`           | `domain: string`                                   |
| SOA      | 6      | `SOA`             | `primary, admin, serial, refresh, retry, expiration, minimum` |
| PTR      | 12     | `PTR`             | `domain: string`                                   |
| MX       | 15     | `MX`              | `exchange, priority`                               |
| TXT      | 16     | `TXT`             | `data: string \| string[]`                         |
| AAAA     | 28     | `AAAA`            | `address: string` (IPv6 colon)                     |
| SRV      | 33     | `SRV`             | `priority, weight, port, target`                   |
| NAPTR    | 35     | `NAPTR`           | `order, preference, flags, services, regexp, replacement` |
| EDNS     | 41     | `EDNS`            | `rdata: EdnsOption[]` (see [EDNS guide](edns.md))  |
| DS       | 43     | `DS`              | `keyTag, algorithm, digestType, digest`            |
| SSHFP    | 44     | `SSHFP`           | `algorithm, fpType, fingerprint`                   |
| RRSIG    | 46     | `RRSIG`           | DNSSEC signature record                            |
| NSEC     | 47     | `NSEC`            | `nextDomain, rdtypes`                              |
| DNSKEY   | 48     | `DNSKEY`          | `flags, protocol, algorithm, key`                  |
| NSEC3    | 50     | `NSEC3`           | `hashAlgorithm, flags, iterations, salt, nextHashedOwner, rdtypes` |
| TLSA     | 52     | `TLSA`            | `usage, selector, matchingType, certificate`       |
| SVCB     | 64     | `SVCB`            | `priority, target, params` (RFC 9460)              |
| HTTPS    | 65     | `HTTPS`           | same wire format as SVCB, different code           |
| SPF      | 99     | `SPF`             | `data: string \| string[]`                         |
| TSIG     | 250    | `TSIG`            | see the [TSIG guide](tsig.md)                      |
| CAA      | 257    | `CAA`             | `flags, tag, value`                                |

The constants in `PacketTypes` (e.g. `PacketTypes.AAAA`) match the IANA
codes in the table above.

## Construction

Every record gets wrapped in a `PacketResource`, which adds the owner name,
class, and TTL:

```ts
import {PacketResource, PacketClass, A, AAAA, MX} from 'dns2ts';

new PacketResource('example.com', new A('192.0.2.1'), PacketClass.IN, 300);
new PacketResource('example.com', new AAAA('2001:db8::1'), PacketClass.IN, 300);
new PacketResource('example.com', new MX('mail.example.com', 10), PacketClass.IN, 300);
```

Push these onto `packet.answers`, `packet.authorities`, or
`packet.additionals` as needed.

## Per-type notes

### A / AAAA

Plain string addresses. IPv6 accepts the canonical form (`::` for runs of
zero, lowercase hex). Helpers in `IP` convert between strings and segment
arrays if you need to manipulate them.

```ts
new A('192.0.2.1');
new AAAA('2001:db8::1');
```

### CNAME / NS / PTR

All three are simple "name pointer" records. The library does **not**
validate that a name resolves; it only encodes/decodes the wire form. Domain
names are length-prefixed labels per RFC 1035, with compression on encode.

### MX

```ts
new MX('mail.example.com', 10);   // exchange, priority
```

The constructor takes `exchange` first, `priority` second, mirroring the
order convention in `MX 10 mail.example.com.` zone-file lines.

### TXT / SPF

Both classes share an implementation. The single-string form is the common
case; the array form lets you produce multiple `<character-string>` items
(useful for long DKIM keys split across boundaries).

```ts
new TXT('v=spf1 include:_spf.example.com ~all');
new TXT(['part1…', 'part2…']);
```

When you parse a multi-string TXT back from the wire, dns2ts joins them
into a single string per RFC 1035 §3.3.14. The original split is not
preserved.

### SOA

```ts
new SOA(
  'ns1.example.com',     // primary
  'admin.example.com',   // admin (no @)
  2024010101,            // serial
  7200,                  // refresh
  3600,                  // retry
  1209600,               // expiration
  3600                   // minimum
);
```

The `admin` field is the responsible-party email with `.` instead of `@`,
per RFC 1035 §3.3.13. The library leaves that conversion to you; pass it
already in dotted form.

### SRV

```ts
new SRV(10, 20, 80, 'www.example.com');   // priority, weight, port, target
```

### CAA

```ts
new CAA(0, 'issue', 'letsencrypt.org');
```

`flags` is the issuer-critical bit (0 or 128). `tag` is `issue`,
`issuewild`, or `iodef`. `value` is the property value as a string.

### SVCB / HTTPS (RFC 9460)

`HTTPS` is a thin subclass of `SVCB` — same wire format, different type
code. Use `HTTPS` for browser-relevant records (`example.com IN HTTPS …`)
and `SVCB` for the generic form.

```ts
import {HTTPS, SvcParamKey} from 'dns2ts';

new HTTPS(1, 'www.example.com', {
  alpn: ['h3', 'h2'],
  port: 443,
  ipv4hint: ['192.0.2.1'],
  ipv6hint: ['2001:db8::1'],
});
```

`AliasMode` is signaled by `priority = 0`:

```ts
new HTTPS(0, 'svc.example.net', {});
```

Unknown SvcParam keys roundtrip via `params.unknown`:

```ts
new HTTPS(1, '.', {
  unknown: [{key: 99, value: Buffer.from([0x01, 0x02])}],
});
```

The encoder sorts SvcParams by key on the wire (RFC 9460 §2.2 requires it),
so input order doesn't matter.

### TLSA

```ts
new TLSA(3, 1, 1, 'aabbccdd…');   // usage, selector, matchingType, certificate (hex)
```

`certificate` is the matching data as a hex string.

### DNSSEC types (DNSKEY, DS, NSEC, NSEC3, RRSIG)

These are wire-format only — the library parses and emits the records but
does not validate signatures. NSEC/NSEC3 expose `rdtypes` as an array of
`PacketTypes` values (the type bitmap is decoded for you).

```ts
new DNSKEY(256, 3, 13, 'PM8S6PI0Gf8d3HK9gHSVpW3X3zeieMEa+PLCijFuaFgi…');
new DS(12345, 8, 2, 'aabbccdd0011…');
new NSEC('next.example.com', [PacketTypes.A, PacketTypes.MX, PacketTypes.RRSIG, PacketTypes.NSEC]);
new NSEC3(1, 0, 10, 'aabb', 'deadbeef', [PacketTypes.A]);
```

## Unknown types

Anything not in the table above is decoded as `UnknownPacketType`, which
preserves the raw RDATA bytes. Roundtripping such a record produces the same
on-wire bytes; you just can't introspect the structured fields.

```ts
import {UnknownPacketType} from 'dns2ts';

const raw = new UnknownPacketType(99, Buffer.from([0x01, 0x02, 0x03]));
```

This is also why a server can forward queries for unknown types without
data loss.

## Adding your own type

1. Subclass `PacketType` and set `super(typeCode)` in the constructor.
2. Implement `encode(resource, writer)` returning the rdata buffer (with
   the leading 2-byte length).
3. Implement a static `decode(reader, length)`.
4. Register it: `PacketTypeRegistry.getInstance().register(typeCode, MyType)`.

Once registered, `PacketResource.decode` will use your class for that type
code, and the index module can re-export it like the built-ins.