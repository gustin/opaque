# OPAQUE Protocol

The OPAQUE protocol is an asymmetric password-authenticated key exchange, PAKE.

A PAKE is a way to exchange cryptographic keys with the knowledge of a password.
The asymmetric part of this aPAKE means that only one party knows the actual
password; the password does not have to be revealed to both parties taking
part in the exchange.

OPAQUE is an IETF candidate for aPAKE recommendation.

## Key Exchange

This package currently uses a custom implementation of the battle-tested
[SIGMA](https://webee.technion.ac.il/~hugo/sigma-pdf.pdf) family of key-exchange
protocols. The full-fledged version, protecting identity.

## OPRF

OPAQUE interleaves an oblivious pseudorandom function, an oblivious pseudo-random
protocol (OPRF) and a key-exchange protocol.

An (OPRF)[https://tools.ietf.org/html/draft-irtf-cfrg-voprf-02] is a way for
two parties to take part in a computation in which one party provides the input
to the computation, and the other party performs the computation. The exciting
part is that the party performing the calculation does not learn anything about the
inputs provided, and the party providing the actual inputs only learns the outputs
and nothing else about the computation.

A verifiable OPRF would enable each party to prove that the computation
was valid; this is a planned improvement.


## Plug-n-Play

The plan is for the key-exchanges, and other cryptographic primitives, to be
plug and played to take part in the overarching protocol.


## Execute

    cargo run --bin opaque

## Security

OPAQUE has been proven to be resilient against pre-computation attacks
in this [whitepaper](https://eprint.iacr.org/2018/163.pdf).

OPAQUE exhibits forward secrecy.

The main attack is a basic brute force, the ability to attempt password
authentication repeatedly. Limiting this attack can easily be accomplished
through standard rate-limiting.

If the database containing the encrypted envelops was stolen, a brute
force attack, emulating this protocol, could be used. The passwords
are stretched in a way to make this computationally intensive. Cryptographic
ways to mitigate this will be explored.


@[:markdown](ToDo.md)

🎸 NOTE: There has not been a security audit performed on this package. 🎸



