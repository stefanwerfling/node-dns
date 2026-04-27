# Zone files

dns2ts ships an RFC 1035 master file parser plus a `Zone` class that wraps
the parsed records with helpers for authoritative serving and AXFR.

## What "zone file" means

A *zone file* (also "master file") is a text representation of a DNS zone
— the SOA, the NS records, and every other record under the zone's apex.
It's the format BIND, NSD, Knot, and most authoritative servers consume on
disk:

```dns
$ORIGIN example.com.
$TTL 3600

@   IN SOA  ns1 admin (
        2024010101  ; serial
        7200        ; refresh
        3600        ; retry
        1209600     ; expire
        3600 )      ; minimum

@   IN NS   ns1
@   IN NS   ns2
@   IN MX   10 mail
www IN A    192.0.2.1
www IN AAAA 2001:db8::1
mail IN A   192.0.2.2
```

## Parsing — `ZoneParser`

The low-level entry point is `ZoneParser.parse(text, options?)`:

```ts
import {ZoneParser} from 'dns2ts';

const {origin, records} = ZoneParser.parse(text, {
  origin: 'example.com',     // used when the file omits $ORIGIN
  defaultTtl: 3600,          // used when both $TTL and per-record TTL are absent
});
```

Returns:

- `origin` — the effective origin after `$ORIGIN` directives, always with a
  trailing dot (`example.com.`).
- `records` — array of `PacketResource` objects ready to be put into a
  `Packet.answers` section or stored in a `Zone`.

### Supported syntax

- **Comments** — `;` to end of line, except inside quoted strings.
- **Multi-line records** — wrap fields in `( … )`. Common for SOA.
- **Quoted strings** — `"…"` with `\"` and `\\` escapes. TXT records
  preserve the quoted content as-is, including spaces and `;` inside.
- **`$ORIGIN`** — sets the suffix appended to relative names. Must end with
  a dot. dns2ts auto-appends one if missing.
- **`$TTL`** — default TTL for records that omit one.
- **`@`** — shortcut for the current origin.
- **Owner-name inheritance** — per RFC 1035 §5.1, a line that begins with
  whitespace inherits the owner name of the previous record:

  ```dns
  www 60 IN A    192.0.2.1
            IN A 192.0.2.2     ; inherits "www"
  ```

- **TTL / class inheritance** — both default to the previous record's value
  when omitted.
- **Class** — `IN`, `CH`, `HS`, `ANY`. Most files use `IN` exclusively.

### Supported RDATA types

The parser dispatches RDATA parsing per type. The 10 most common are
covered:

A, AAAA, NS, CNAME, PTR, MX, TXT (incl. multiple character-strings), SOA,
SRV, CAA.

Unsupported types raise a clear error with the offending line number
rather than silently dropping data:

```
Error: line 14: unsupported record type AFSDB
```

If you need a type that isn't in the list — DNSKEY, DS, RRSIG, NSEC, NSEC3,
TLSA, SSHFP, NAPTR, SVCB, HTTPS — the structured wire-format classes exist;
the zone-file form just isn't wired up yet. Contributions welcome.

### Not yet supported

- **`$INCLUDE`** — would require filesystem access; not yet implemented.
- **Generic encoding `\#`** (RFC 3597) — would let arbitrary RR types be
  parsed by length+hex; not yet implemented.
- **DNSSEC RDATA in zone-file syntax** — see above; the wire-format types
  exist, the text parser doesn't dispatch to them yet.

### Errors

| Error                                          | Cause                                                   |
| ---------------------------------------------- | ------------------------------------------------------- |
| `unmatched ')' at line N`                      | More closing than opening parens                        |
| `unmatched '(' starting near line N`           | Opening paren without a matching close at EOF           |
| `unterminated quoted string starting near line N` | Quote opened, file ended before closing                  |
| `line N: name required (no previous record …)` | Leading-whitespace line with no prior record to inherit |
| `line N: unsupported record type X`            | Type not in the supported list                          |
| `line N: unsupported directive $X`             | Anything other than `$ORIGIN` and `$TTL`                |

## Higher-level API — `Zone`

`Zone` wraps the parser output for the common case "I want this file as a
zone object I can serve from".

```ts
import {Zone} from 'dns2ts';

const zone = Zone.fromZoneFile(text, {origin: 'example.com'});

zone.origin;                                  // 'example.com.'
zone.records.length;                          // every record, SOA included
zone.soa();                                   // the SOA PacketResource (throws if absent)
zone.soaRdata().serial;                       // shortcut to SOA fields

for (const ns of zone.recordsOfType(PacketTypes.NS)) {
  console.log(ns.name, ns.packetType);
}
```

`zone.toAxfrPackets(query)` produces the AXFR response packets — see the
[AXFR guide](axfr.md).

## Loading from disk

Wherever you read the file, normalize the line endings if the source might
be CRLF. The parser handles `\r` as whitespace, but mixed CR/LF won't break
it.

```ts
import {readFile} from 'fs/promises';
import {Zone} from 'dns2ts';

const text = await readFile('/etc/dns2ts/zones/example.com.zone', 'utf8');
const zone = Zone.fromZoneFile(text);
```

## Serializing

There is **no zone-file writer** yet — dns2ts can read and emit wire format
but does not regenerate zone-file text from records. If you need to dump a
zone to text, iterate `zone.records` and format each record by type. Pull
requests adding a writer are welcome.

## Indented zone files in tests

If you embed zone strings in TypeScript test files using template literals,
the leading indent on every line will be interpreted as "inherit the
previous owner name" — the opposite of what you usually want. The test
suite ships a small `dedent` helper for this; you can use the same trick:

```ts
const dedent = (s: string): string => {
  const lines = s.split('\n');
  let min = Infinity;
  for (const ln of lines) {
    if (ln.trim() === '') continue;
    const m = ln.match(/^[ \t]*/);
    if (m) min = Math.min(min, m[0].length);
  }
  return min === Infinity || min === 0 ? s : lines.map(l => l.slice(min)).join('\n');
};

const zone = Zone.fromZoneFile(dedent(`
  $ORIGIN example.com.
  www IN A 192.0.2.1
`));
```

For real files read from disk, this is a non-issue — they're not indented
in the first place.