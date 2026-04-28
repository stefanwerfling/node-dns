# DNSSEC validation

`Dnssec` is a stateless verification layer on top of the existing DNSKEY,
DS and RRSIG record types. You feed it an RRset, the matching RRSIG, and
a candidate DNSKEY, and it returns a boolean. There is no resolver, no
cache, no chain traversal — that lives one layer up.

The implementation tracks the RFCs that every validating resolver agrees
on:

- [RFC 4033](https://datatracker.ietf.org/doc/html/rfc4033) — DNSSEC introduction and requirements
- [RFC 4034](https://datatracker.ietf.org/doc/html/rfc4034) — DNSKEY / DS / RRSIG / NSEC RDATA
- [RFC 4035](https://datatracker.ietf.org/doc/html/rfc4035) — Protocol modifications, validation steps
- [RFC 4509](https://datatracker.ietf.org/doc/html/rfc4509) — SHA-256 in DS records
- [RFC 5155](https://datatracker.ietf.org/doc/html/rfc5155) — NSEC3
- [RFC 6605](https://datatracker.ietf.org/doc/html/rfc6605) — ECDSA P-256 / P-384
- [RFC 6840](https://datatracker.ietf.org/doc/html/rfc6840) — clarifications (no compression for DNSSEC RRs)
- [RFC 8080](https://datatracker.ietf.org/doc/html/rfc8080) — Ed25519 / Ed448

## What's covered

- **Signature verification** for the algorithms that carry the modern
  DNSSEC ecosystem:

  | Algo | Name              | Hash       | Use      |
  | ---: | ----------------- | ---------- | -------- |
  |    8 | RSA/SHA-256       | SHA-256    | most common |
  |   10 | RSA/SHA-512       | SHA-512    | larger keys, less common |
  |   13 | ECDSA P-256       | SHA-256    | recommended for new zones (RFC 8624) |
  |   14 | ECDSA P-384       | SHA-384    | high-security zones |
  |   15 | Ed25519           | EdDSA      | recommended for new zones (RFC 8624) |

  Older algorithms (5 RSA/SHA-1, 7 RSASHA1-NSEC3, 16 Ed448, 1 RSA/MD5,
  3 DSA) throw an `unsupported algorithm` error. Per RFC 8624 the older
  ones are MUST-NOT-sign anyway and validators are not required to
  support them.

- **DS digest computation and matching** for digest types 1 (SHA-1),
  2 (SHA-256, MUST per RFC 8624), 4 (SHA-384). `Dnssec.verifyDs`
  cross-checks key tag, algorithm, and digest in one call.

- **Key tag computation** per [RFC 4034 Appendix B](https://datatracker.ietf.org/doc/html/rfc4034#appendix-B).

## What's *not* covered (yet)

This library stops short of the message-shape conventions a recursive
resolver imposes. The cryptographic primitives are all here. A
production validator on top of dns2ts still has to:

- **Walk the chain of trust** from a configured trust anchor (the root
  KSK) down to the zone whose answer it's validating. That requires a
  recursive resolver — see the roadmap.
- **Compose end-to-end NXDOMAIN / NODATA proofs** from the NSEC /
  NSEC3 building blocks below. The shape of the proof depends on what
  the authoritative server returned (closest-encloser candidate,
  wildcard, opt-out flag, …); we leave that to the resolver layer
  rather than picking a calling convention here.
- **Sign your own zones**. The library only verifies. If you operate
  the authoritative side, you'll need an external signer (BIND
  `dnssec-signzone`, Knot's `keymgr`, OpenDNSSEC, ldns-signzone) for
  now.

Wildcard owner-name reconstruction *is* covered — when `rrsig.labels`
is less than the owner's actual label count, the verifier infers
`*.<trailing labels>` as the signed owner per [RFC 4034 §3.1.3](https://datatracker.ietf.org/doc/html/rfc4034#section-3.1.3)
before computing the signing input. Just pass the expanded owner name
(the one returned in the answer) to `verifyRrsig` and the
reconstruction happens automatically.

Canonical RDATA is implemented for every record type the library
parses. If you wire up a brand-new record type with embedded domain
names, add a case to `Dnssec._canonicalRdataBytes` per [RFC 4034 §6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).

## Verifying an RRset

```ts
import {Dnssec} from 'dns2ts';

const valid = Dnssec.verifyRrsig(
  'example.com',           // owner name (canonicalized internally)
  rrset,                   // PacketResource[] — every RR with this name+type
  rrsig,                   // RRSIG record covering the RRset
  dnskey,                  // candidate DNSKEY (key tag + algo must match)
);

if (!valid) {
  // Either the signature doesn't match, the key tag/algorithm don't
  // pair, or the signature is outside its inception/expiration window.
}
```

The return value is `false` for any of: mismatched key tag, mismatched
algorithm, signature outside the validity window, cryptographic
mismatch. `verifyRrsig` only **throws** when it cannot judge — typically
when the algorithm isn't supported or the RDATA contains an embedded
name we don't know how to canonicalize yet.

### Tampering or test scenarios

If you need to ignore the inception/expiration window — replaying a
captured signature, testing with frozen fixtures — pass
`skipValidityWindow: true`:

```ts
Dnssec.verifyRrsig(owner, rrset, rrsig, dnskey, {skipValidityWindow: true});
```

To pin the "current time" without leaving the window check off, pass
`now` as a Unix-seconds value:

```ts
Dnssec.verifyRrsig(owner, rrset, rrsig, dnskey, {now: 1735689600});
```

## Verifying a DS record

`DS` records sit at the parent zone and commit to a child zone's
DNSKEY. To check that a DNSKEY you fetched matches the DS the parent
publishes:

```ts
const matches = Dnssec.verifyDs('example.com', dnskey, ds);
```

This compares key tag, algorithm, and digest in one call. If you want
the digest yourself (for emitting a fresh DS record alongside a key
roll, for example):

```ts
const digestHex = Dnssec.computeDsDigest('example.com', dnskey, 2 /* SHA-256 */);
```

## Negative-answer building blocks

NSEC and NSEC3 prove a non-existence claim. The records get fetched
and parsed by the existing types; the question is then "does this
specific NSEC / NSEC3 record cover the queried name?" These primitives
answer that question:

```ts
// Right-to-left, label-by-label, octet-compare canonical order
// (RFC 4034 §6.1). Returns -1, 0, or +1.
Dnssec.canonicalNameCompare('z.example.com', 'a.example.com');  // +1

// NSEC: does an NSEC RR at `owner` with NextDomain `next` prove
// `query` doesn't exist? Handles the end-of-zone wrap-around case
// (the last NSEC's NextDomain points back at the apex, so
// `next < owner` canonically — anything strictly between owner and
// the apex is still covered).
Dnssec.nsecCovers('a.example.com', 'c.example.com', 'b.example.com'); // true
Dnssec.nsecCovers('z.example.com', 'example.com', 'zz.example.com');  // wrap-around

// NSEC3: hash a name per RFC 5155 §5. The iterations field counts
// *additional* rounds, so iterations=N means N+1 SHA-1 calls.
// algorithm defaults to 1 (SHA-1) — RFC 9276 forbids any other
// value in production.
const hash = Dnssec.nsec3Hash('host.example.com', 'aabbccdd', 12);

// Compare a 20-byte query hash against a chain entry's owner-hash and
// nextHashedOwner (also 20 bytes each). Same wrap-around logic as
// nsecCovers, just on raw bytes.
Dnssec.nsec3CoversHash(ownerHashBuf, nextHashBuf, hash);

// RFC 4648 §7 base32hex (extended-hex alphabet, no padding) for
// rendering an NSEC3 hash as the first label of a hashed owner name.
Dnssec.base32hexEncode(hash);  // 32-char lowercase string
```

`nsec3Hash` matches the published RFC 5155 Appendix A.1 fixtures
exactly — the test suite checks all 11 hashed names from the example
zone (`example.`, `a.example.`, `*.w.example.`, `xx.example.`, …).

### When you'd compose these

A typical NSEC3 NXDOMAIN proof needs three records: the NSEC3 of the
closest encloser, the NSEC3 covering the "next-closer name" (one label
longer than the encloser, on the path to the queried name), and the
NSEC3 covering `*.<closest-encloser>`. The shape varies for NODATA
answers, opt-out delegations, and DS / wildcard cases. A library-level
`Dnssec.proveNxdomain(...)` would have to pick one calling convention
for all of those — which is something better done where the
authoritative answer arrives. So instead we expose `nsec3Hash` and
`nsec3CoversHash` and let you write the composition once your resolver
knows what shape it has.

## Computing a key tag

```ts
const keyTag = Dnssec.computeKeyTag(dnskey);
```

The 16-bit folded checksum is the same algorithm every validator uses,
defined in [RFC 4034 Appendix B](https://datatracker.ietf.org/doc/html/rfc4034#appendix-B).
RRSIG records reference the signing DNSKEY by this tag, so a working
validator must compute it identically.

## Worked example — generate, sign, verify

The test suite (`src/Test/dnssec.ts`) doubles as a worked example. The
gist is:

```ts
import * as crypto from 'crypto';
import {Dnssec, DnssecAlgorithm, A, DNSKEY, RRSIG, PacketClass, PacketResource, PacketTypes} from 'dns2ts';

// 1. Generate an Ed25519 key pair
const {publicKey, privateKey} = crypto.generateKeyPairSync('ed25519');

// 2. Wrap the public key in a DNSKEY
const jwk = publicKey.export({format: 'jwk'}) as {x: string;};
const dnskey = new DNSKEY(257, 3, DnssecAlgorithm.ED25519,
  Buffer.from(jwk.x, 'base64url').toString('base64'));

// 3. Build the RRset and the RRSIG header
const owner = 'example.com';
const rrset = [
  new PacketResource(owner, new A('192.0.2.1'), PacketClass.IN, 3600),
];
const rrsig = new RRSIG(
  PacketTypes.A,                  // typeCovered
  DnssecAlgorithm.ED25519,        // algorithm
  owner.split('.').length,        // labels
  3600,                           // originalTtl
  '20300101000000',               // expiration
  '20240101000000',               // inception
  Dnssec.computeKeyTag(dnskey),   // keyTag
  owner,                          // signer
  ''                              // signature — patched below
);

// 4. Compute the signing input the same way the verifier will, then sign
const input = Dnssec.buildSigningInput(owner, rrset, rrsig);
rrsig.signature = crypto.sign(null, input, privateKey).toString('base64');

// 5. Verify
console.log(Dnssec.verifyRrsig(owner, rrset, rrsig, dnskey)); // true
```

The same shape works for the other algorithms — just swap the key
generation and the `crypto.sign` arguments. For ECDSA, sign with
`{key: privateKey, dsaEncoding: 'ieee-p1363'}` so the output is the
DNS raw `r||s` form rather than DER. The verifier reads it back the
same way; no DER conversion ever happens in the code path.

## Public-key wire formats

`Dnssec` reads the DNSKEY public key directly out of the `dnskey.key`
base64 field and converts it to a Node `KeyObject` via JWK import:

- **RSA (algos 8, 10)** — RFC 3110: `[explen | exponent | modulus]`,
  where `explen` is a single byte (1–255) or `0` followed by a uint16.
- **ECDSA P-256 (algo 13)** — 64 raw bytes, `X || Y` (no leading 0x04).
- **ECDSA P-384 (algo 14)** — 96 raw bytes, `X || Y`.
- **Ed25519 (algo 15)** — 32 raw bytes, the public key.

Malformed lengths throw a descriptive error.

## Canonical form quick reference

When implementing your own DNSSEC tooling against this library, the
canonical-form rules from [RFC 4034 §6](https://datatracker.ietf.org/doc/html/rfc4034#section-6)
that matter most:

1. **Owner names** — lowercased, encoded as length-prefixed labels with
   no DNS compression.
2. **Embedded names in RDATA** — also lowercased, also uncompressed,
   for the RR types listed in §6.2 step 2 (NS, MD, MF, CNAME, SOA, MB,
   MG, MR, PTR, HINFO, MINFO, MX, RP, AFSDB, RT, SIG, PX, NXT, NAPTR,
   KX, SRV, DNAME, A6, RRSIG, NSEC).
3. **RR sort order in an RRset** — by canonical RDATA bytes,
   left-to-right unsigned (`Buffer.compare` semantics).
4. **TTL** — substituted with `RRSIG.originalTtl` for the signing input.
5. **No compression for DNSSEC RR types** — RFC 6840 §5.1: DNSKEY,
   NSEC, NSEC3, RRSIG, DS must be transmitted uncompressed, regardless
   of canonical-form considerations.

`Dnssec.buildSigningInput` is the reference implementation — read it if
you're adding canonical RDATA support for a new type.