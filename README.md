# OPAQUE Protocol (Draft-03 Reference Implementation)

> **For production use, see [opaque-ke](https://github.com/facebook/opaque-ke)** - the audited, RFC 9807-compliant Rust implementation from Meta.

This repository is a **historical reference implementation** of the OPAQUE protocol targeting [draft-krawczyk-cfrg-opaque-03](https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-03) (October 2019).

OPAQUE has since been finalized as [RFC 9807](https://www.rfc-editor.org/rfc/rfc9807) (July 2025) with significant protocol changes. This codebase documents what the early draft looked like before the CFRG working group refined it into the final standard.

## What's Here

A Rust implementation of draft-03 OPAQUE featuring:
- Custom DH-OPRF with multiplicative blinding
- SIGMA-I key exchange (signature-based)
- AES-GCM-SIV encrypted envelopes
- Ristretto group operations via curve25519-dalek

## What Changed (draft-03 → RFC 9807)

The final RFC is essentially a complete rewrite:

| Aspect | This Implementation (draft-03) | RFC 9807 |
|--------|-------------------------------|----------|
| Key Exchange | SIGMA-I (signatures) | 3DH (MACs only) |
| Envelope | Encrypted credentials | Auth-only, derived keys |
| OPRF | Custom with `v=g^k` in hash | RFC 9497 standard |
| Password stretch | Optional | Required (Argon2id) |

See [`docs/specs/SPEC_DIFF.md`](docs/specs/SPEC_DIFF.md) for the full breakdown.

## For Production

Use **[opaque-ke](https://crates.io/crates/opaque-ke)**:

```toml
[dependencies]
opaque-ke = "4.0"
```

It's:
- RFC 9807 compliant
- Audited by NCC Group (sponsored by WhatsApp)
- Battle-tested in production
- Actively maintained

## Background

OPAQUE is an asymmetric password-authenticated key exchange (aPAKE) where only the client knows the password - the server never sees it, even during registration.

I discovered OPAQUE through Matthew Green's blog post: [Let's talk about PAKE](https://blog.cryptographyengineering.com/2018/10/19/lets-talk-about-pake/)

### Threshold OPAQUE

OPAQUE lends itself to threshold schemes to mitigate database compromise. A threshold protocol distributes a private key amongst servers - a certain number (the threshold) is needed to participate.

In the OPRF case, each server acts as an OPRF signer of the blinded salt from the client. Each server holds a share of the larger private key. The OPRF output requires a threshold number of servers to participate in its generation.

Each server runs a [Distributed Key Generation](https://en.wikipedia.org/wiki/Distributed_key_generation) protocol to generate their share. Torben Pedersen first specified such a protocol in 1991:
https://pdfs.semanticscholar.org/642b/d1bbc86c7750cef9fa770e9e4ba86bd49eb9.pdf

The Feldman VSS (verifiable secret sharing) is a way to participate in DKG:
https://ieeexplore.ieee.org/abstract/document/4568297/

More references:
- [Threshold OPRF paper](https://eprint.iacr.org/2017/363.pdf)
- [NIST Threshold Cryptography project](https://csrc.nist.gov/Projects/threshold-cryptography)

### Security

OPAQUE has a [formal security proof](https://eprint.iacr.org/2018/163.pdf) showing resilience against pre-computation attacks and forward secrecy. Main attack vectors are online brute force (mitigate with rate-limiting) and offline attacks on stolen envelopes (mitigate with password stretching).

## Draft History

This implementation targets **draft-03** (October 2019). The spec evolved significantly:

**Draft 4** (May 2020): Envelope construction clarified (AES-CTR + HMAC), 3DH added, OPRF simplified (removed `v=g^k` from hash).

**Draft 5** (May 2020): Clarifications, prep for formal spec.

**RFC 9807** (July 2025): Complete rewrite - 3DH as primary KE, authentication-only envelope with derived keys, mandatory Argon2id, RFC 9497 OPRF.

## References

- [Original OPAQUE paper](https://eprint.iacr.org/2018/163.pdf) (Jarecki, Krawczyk, Xu - Eurocrypt 2018)
- [CFRG PAKE selection](https://github.com/cfrg/pake-selection)
- [RFC 9807 - OPAQUE](https://www.rfc-editor.org/rfc/rfc9807)
- [RFC 9497 - OPRF](https://www.rfc-editor.org/rfc/rfc9497)

## Specs

The `docs/specs/` directory contains:
- `draft-krawczyk-cfrg-opaque-03.txt` - the spec this implementation targets
- `rfc9807.txt` - the final RFC
- `SPEC_DIFF.md` - detailed migration analysis

## License

BSD 3-Clause
