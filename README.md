# The OPAQUE Asymmetric PAKE Protocol

(RFC)[https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-02#section-3.1]

    cargo run --bin opaque


## A Note on Signature Malleability

Note in the curve25519-dalek readme:

"The signatures produced by this library are malleable, as discussed in the original (paper)[https://ed25519.cr.yp.to/ed25519-20110926.pdf]:

We could eliminate the malleability property by multiplying by the curve cofactor, however,
this would cause our implementation to not match the behaviour of every other implementation
in existence. As of this writing, RFC 8032, "Edwards-Curve Digital Signature Algorithm (EdDSA),
" advises that the stronger check should be done. While we agree that the stronger check should
be done, it is our opinion that one shouldn't get to change the definition of "ed25519 verification"
a decade after the fact, breaking compatibility with every other implementation.

In short, if malleable signatures are bad for your protocol, don't use them. Consider using a
curve25519-based Verifiable Random Function (VRF), such as Trevor Perrin's (VXEdDSA)[https://signal.org/docs/specifications/xeddsa/],
instead.  We plan to eventually support (VXEdDSA)[https://github.com/dalek-cryptography/curve25519-dalek/issues/9] in curve25519-dalek."

## General notes

Consider using Subtle for constant time: https://github.com/dalek-cryptography/subtle

Zero out memory with: https://lib.rs/crates/zeroize

Use Ring for CSPRING: https://docs.rs/ring/0.16.9/ring/rand/index.html

