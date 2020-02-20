# The OPAQUE Asymmetric PAKE Protocol

🎸 NOTE: No audit has been done on this package. While it appears to work,
there may be security holes.


(RFC)[https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-02#section-3.1]

    cargo run --bin opaque

## General notes

Consider using Subtle for constant time: https://github.com/dalek-cryptography/subtle

Zero out memory with: https://lib.rs/crates/zeroize

Use Ring for CSPRING: https://docs.rs/ring/0.16.9/ring/rand/index.html

## WASM

    rustup target add wasm32-unknown-unknown

    cargo check --target wasm32-unknown-unknown

    cargo build --target wasm32-unknown-unknown


