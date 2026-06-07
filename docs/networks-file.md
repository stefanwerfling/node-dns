# `/etc/networks` parser — `NetworksFile`

`NetworksFile` reads `/etc/networks` (the [`networks(5)`][man]
companion to `/etc/hosts`) and exposes name ↔ address lookups
over its entries. Useful for tools that classify IP traffic by
symbolic network name — observability stacks, reverse-DNS
pretty-printing of subnet ranges, routing UIs.

`/etc/networks` is **not** part of the DNS resolution path. dns2ts
ships the parser as a standalone utility rather than wiring it
into `SystemResolver` because `resolver(5)` doesn't consult it.

[man]: https://man7.org/linux/man-pages/man5/networks.5.html

## Format

```
# /etc/networks
default        0.0.0.0
loopback       127.0.0.0
link-local     169.254
mynet          192.168.1     home  lan
```

Per the spec:

- One entry per line: `name address [aliases...]`.
- Comments start with `#` (rest of line ignored).
- Addresses are **IPv4 only**, and may be abbreviated to as few
  octets as needed — `127` expands to `127.0.0.0`, `192.168` to
  `192.168.0.0`, `192.168.1` to `192.168.1.0`.
- Names and aliases are case-insensitive (the parser lowercases
  them).
- Malformed lines are silently skipped — `getnetbyname(3)` is
  tolerant.

## Reading the file

```ts
import {NetworksFile} from 'dns2ts';

const networks = NetworksFile.fromFile();              // /etc/networks
const custom   = NetworksFile.fromFile('/path/to/networks');
const inline   = NetworksFile.parse('loopback 127\n'); // from a string
```

`fromFile()` returns an empty `NetworksFile` on `ENOENT` /
`EACCES` / `EPERM` (matching glibc's tolerance) and re-throws on
other I/O errors.

## Lookups

```ts
const lo = networks.lookupByName('loopback');
// → { name: 'loopback', address: '127.0.0.0', aliases: [] }

const home = networks.lookupByName('home');     // alias-aware
// → { name: 'mynet', address: '192.168.1.0', aliases: ['home', 'lan'] }

const byAddr = networks.lookupByAddress('169.254.0.0');
// → { name: 'link-local', address: '169.254.0.0', aliases: [] }

const byBuffer = networks.lookupByAddress(Buffer.from([127, 0, 0, 0]));
// → { name: 'loopback', address: '127.0.0.0', aliases: [] }

const shortForm = networks.lookupByAddress('127');
// → same as above — the short form is normalized before lookup
```

`lookupByAddress` returns `null` for non-matching addresses, for
non-IPv4 input, and for `Buffer` arguments that aren't exactly
4 bytes.

## Stacking files — `merge`

`merge(other)` stacks two `NetworksFile` instances; the receiver
wins on both name and address collisions. Useful when you want a
local override file on top of the system one:

```ts
const base    = NetworksFile.fromFile('/etc/networks');
const overlay = NetworksFile.fromFile('/etc/networks.local');
const stacked = base.merge(overlay);
```

## What's not implemented

- IPv6. `networks(5)` is IPv4-only by spec; rare hand-rolled IPv6
  entries you might see in the wild are not supported.
- File watching. `/etc/networks` doesn't typically change at
  runtime; if you need hot-reload, mirror the `HostsFile.watch()`
  pattern in your own code.
- `SystemResolver` integration. `resolver(5)` doesn't consult
  `/etc/networks`, and neither does dns2ts's stub resolver.