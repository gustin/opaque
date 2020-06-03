# OPAQUE Protocol
The OPAQUE protocol is an asymmetric password-authenticated key exchange, PAKE.

A [PAKE](https://en.wikipedia.org/wiki/Password-authenticated_key_agreement)
is a way to exchange cryptographic keys with the knowledge of a password.
The asymmetric part of this aPAKE means that only one party knows the actual
password; the password does not have to be revealed to both parties taking
part in the exchange.

OPAQUE was selected by the CFRG as the aPake of choice:
https://github.com/cfrg/pake-selection

I discovered OPAQUE through Matthew Green's blog post:
[Let's talk about PAKE](https://blog.cryptographyengineering.com/2018/10/19/lets-talk-about-pake/)

## Key Exchange

This package currently uses a custom implementation of the battle-tested
[SIGMA](https://webee.technion.ac.il/~hugo/sigma-pdf.pdf) family of key-exchange
protocols. The full-fledged version, protecting identity.

## OPRF

OPAQUE interleaves an oblivious pseudorandom function (OPRF) and a key-exchange
protocol.

An (OPRF)[https://tools.ietf.org/html/draft-irtf-cfrg-voprf-03] is a way for
two parties to take part in a computation in which one party provides the input
to the computation, and the other party performs the computation.

The exciting part is that the party performing the calculation learns nothing
about the inputs provided, and the party providing the actual inputs
only learns the outputs and nothing else about the computation.


### Verifiable

A verifiable OPRF, a vOPRF, enables each party to prove that the computation
was valid.

## Threshold

OPAQUE lends itself to the ability to a threshold to mitigate a data store being
stolen or accessed.

A threshold protocol basically distributes a private key amongst a bunch of servers.
A certain a certain number of servers, the threshold, is needed to take part in a protocol.

NIST is working to standardize the threshold schemes for cryptographic primitives:
https://csrc.nist.gov/Projects/threshold-cryptography

### Threshold OPRF

An OPRF can become a threshold OPRF:
https://eprint.iacr.org/2017/363.pdf

In the OPRF case, each server acts as a OPRF signer of the blinded salt from the client.
Each server takes part as a share of the larger private key. The output from the OPRF
can then be required to have a certain number of servers take part in its generation.

Each server runs a [Distributed Key Generation protocol](https://en.wikipedia.org/wiki/Distributed_key_generation)
to generate their share of the private key.

Torben Pedersen first specified a protocol in 1991:
https://pdfs.semanticscholar.org/642b/d1bbc86c7750cef9fa770e9e4ba86bd49eb9.pdf

The Feldman VSS (verifiable secret sharing) is a way to take part in the DKG:
https://ieeexplore.ieee.org/abstract/document/4568297/

## Security

🎸 There has not been a security audit performed on this package. 🎸

OPAQUE has been proven to be resilient against pre-computation attacks
in this [whitepaper](https://eprint.iacr.org/2018/163.pdf).

OPAQUE exhibits forward secrecy.

It is one of the few PAKEs with a security proof:
https://eprint.iacr.org/2018/163.pdf

The main attack is a basic brute force, the ability to attempt password
authentication repeatedly. Limiting this attack can easily be accomplished
through standard rate-limiting.

If the database containing the encrypted envelops was stolen, a brute
force attack, emulating this protocol, could be used. The passwords
are stretched in a way to make this computationally intensive. Cryptographic
ways to mitigate this will be explored.

🎸 There has not been a security audit performed on this package. 🎸

## Draft Version

This library is currently built against [draft version 3](https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-03).

[Draft 4 of Opaque](https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-04) was
released on May 15th, 2020.

The main changes seem to be:
  * Details on how to build out the user Envelope:
      * specified using AES-CTR and HMAC
      * only encrypt-then-MAC is recommended
      * GCM is allowed, but only GCM-then-HMAC
  * Key exchange protocols is expanded:
      * 3DH is added to the already described HMQV and SIGMA-I
  * OPRF definition changed
      * Does not include `vU = g^kU` when hashing
      * This was proven to not be needed anymore

[Draft 5 of Opaque](https://www.ietf.org/id/draft-krawczyk-cfrg-opaque-05.txt) was
released on May 29th, 2020.

This will be the last change before a formal specification.

The main changes for Draft 5 are mostly clarifications and added TODOs to prepare
for specification.

## Things to do..

A more detailed list of things Todo:
@[:markdown](ToDo.md)

## Execute

    cargo run --bin opaque

## Testing

A set of OPAQUE test vectors are tested against:

    cargo test



