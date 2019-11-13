use opaque::registration;

use rand_os::OsRng;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::Sha512;

use x25519_dalek::EphemeralSecret;
use x25519_dalek::PublicKey;

fn OPRF() {
    // OPAQUE uses a specific OPRF instantiation, called DH-OPRF, where the
    // PRF, denoted F, is defined as follows.

    // ***> Spec

    // Parameters: Hash function H (e.g., a SHA2 or SHA3 function), a cyclic
    // group G of prime order q, a generator g of G, and hash function H'
    // mapping arbitrary strings into G (where H' is modeled as a random
    // oracle).

    // o  DH-OPRF domain: Any string
    // o  DH-OPRF range: The range of the hash function H
    // o  DH-OPRF key: A random element k in [0..q-1]; denote v=g^k
    // o  DH-OPRF Operation: F(k; x) = H(x, v, H'(x)^k)

    // ***> Impl
    // Parameters:

    // Hash function H (e.g. a SHA2 or SHA3)
    //    blake::hash(256, b"password", &mut alpha).unwrap();

    // a cyclic group G of prime order q
    // -> G is the Ristretto group of prime order q

    // a generator g of G
    // -> g is something that can return a point from the group,
    // from the Ed25519 curve
    // RistrettoPoint::random(), which generates random points from an RNG;

    // Uses the Ristretto-flavoured Elligator 2 map, so that the discrete
    // log of the output point with respect to any other point should be unknown.
    // The map is applied twice and the results are added, to ensure a uniform
    // distribution.
    let mut cspring: OsRng = OsRng::new().unwrap();
    let px = RistrettoPoint::random(&mut cspring);
    println!("RistrettoPoint::random(): {:?}", px);

    // a hash function H' mapping arbitrary strings into G
    // where H' is modeled as a random oracle
    // -> This is the hashing of a string to an elliptical
    // curve point.
    // RistrettoPoint::from_hash()
    let msg = "plaintext";
    let hash_prime = RistrettoPoint::hash_from_bytes::<Sha512>(msg.as_bytes());
    println!("Ristretto Point from hash prime function: {:?}", hash_prime);

    // DH-OPRF domain: any string
    // -> "plaintext"
    let domain = "plaintext";

    // DH-OPRF range: The range of the hash function H
    // -> what is the range of the blake2? is it 512? 2^512

    // DH-OPRF key: A random element k in [0..q-1]; denote v=g^k
    // -> This is the key the server generates to feed the OPRF, I think
    // the salt, v is the DH in the DH-OPRF, is k scalar, g is a point?

    // ***> Spec

    // Protocol for computing DH-OPRF, U with input x and S with input k:
    // o  U: choose random r in [0..q-1], send alpha=H'(x)*g^r to S
    // o  S: upon receiving a value alpha, respond with v=g^k and
    // beta=alpha^k
    // o  U: upon receiving values beta and v, set the PRF output to
    // H(x, v, beta*v^{-r})

    // ***> Impl

    // U with input x -> elliptical point? from hash?
    // S inputs k -> k is the salt

    // U: choose random r in [0..q-1]
    let r = RistrettoPoint::random(&mut cspring);
    println!("RistrettoPoint::random(): random r in [0..q-1] {:?}", r);

    // send alpha=H'(x)*g^r
    // H'(x)
    //-let x = "";
    //-hash_prime = RistrettoPoint::hash_from_bytes::<Sha512>(msg.as_bytes());

    // g^r
    let _g = 5;

    // H'(x) * g^r
    //let alpha = hash_prime * px;

    // Scalars
    let a: Scalar = Scalar::random(&mut cspring);
    println!("Rando Scalar: {:?}", a);

    let msg2 = "plaintext";
    let s = Scalar::hash_from_bytes::<Sha512>(msg2.as_bytes());
    println!("Scalar hash from: {:?}", s);

    // invert

    let inverse: Scalar = s.invert();
    println!("Scalar inverse: {:?}", inverse);
}

// https://tools.ietf.org/html/rfc7748
/*
    6.  Diffie-Hellman

    6.1.  Curve25519

    The X25519 function can be used in an Elliptic Curve Diffie-Hellman
    (ECDH) protocol as follows:

    Alice generates 32 random bytes in a[0] to a[31] and transmits K_A =
    X25519(a, 9) to Bob, where 9 is the u-coordinate of the base point
    and is encoded as a byte with value 9, followed by 31 zero bytes.

    Bob similarly generates 32 random bytes in b[0] to b[31], computes
    K_B = X25519(b, 9), and transmits it to Alice.

    Using their generated values and the received input, Alice computes
    X25519(a, K_B) and Bob computes X25519(b, K_A).

    Both now share K = X25519(a, X25519(b, 9)) = X25519(b, X25519(a, 9))
    as a shared secret.  Both MAY check, without leaking extra
    information about the value of K, whether K is the all-zero value and
    abort if so (see below).  Alice and Bob can then use a key-derivation
    function that includes K, K_A, and K_B to derive a symmetric key.

    The check for the all-zero value results from the fact that the
    X25519 function produces that value if it operates on an input
    corresponding to a point with small order, where the order divides
    the cofactor of the curve (see Section 7).  The check may be
    performed by ORing all the bytes together and checking whether the
    result is zero, as this eliminates standard side-channels in software
    implementations.

    Test vector:

    Alice's private key, a:
        77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
    Alice's public key, X25519(a, 9):
        8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
    Bob's private key, b:
        5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
    Bob's public key, X25519(b, 9):
        de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
    Their shared secret, K:
        4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
*/
fn DH() {
    // instead of transmitting a value “x”, the value “2^x (mod p)” is transmitted,
    // where “p” is a large prime number greater than 10⁶⁰⁰.
    //
    // The “mod p” expression means that all multiples of a prime number “p”
    // are removed from the computed value, in order to make the result smaller
    // than “p”.
    //
    // It would be easy for small “x”, but hard for values greater than 10⁶⁰⁰.
    //
    // In the end, the expression 2^(xy) forms the basis to derive a cipher key.
    // (The other user receives 2^y and forms 2^y^x.)
    //
    // a^(p-1) = 1 (mod p)
    //

    let mut cspring = OsRng::new().unwrap();
    let alice_secret = EphemeralSecret::new(&mut cspring);
    let alice_public = PublicKey::from(&alice_secret);

    let bob_secret = EphemeralSecret::new(&mut cspring);
    let bob_public = PublicKey::from(&bob_secret);

    let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);
    let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);
    println!("Alice's Shared: {:?}", alice_shared_secret.as_bytes());
    println!("Bob's Shared: {:?}", bob_shared_secret.as_bytes());
}

fn main() {
    println!("`~- OPAQUE -~'");
    OPRF();
    DH();

    // ***> Spec

    // 3.1.  Password registration
    // https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-02#section-3.1
    // Password registration is run between a user U and a server S.

    // U chooses password PwdU and a pair of private-public keys PrivU
    // and PubU for the given protocol KE

    // CSPRING: just using OS's PRNG for now
    //    let mut csprng: OsRng = OsRng::new().unwrap();
    // Generate a keypair
    //    let keypair: Keypair = Keypair::generate(&mut csprng);
    //    let _public_key: PublicKey = keypair.public;

    // basic password for now
    //    let _password = "fizzbangpopdog";
    //    let _user_id = 8;

    //  Protocol for computing DH-OPRF, U with input x and S with input k:
    //  U: choose random r in [0..q-1], send alpha=H'(x)*g^r to S
    //    let mut alpha = [0; 32];
    //    blake::hash(256, b"password", &mut alpha).unwrap();

    // U and S run OPRF(kU;PwdU) as defined in Section 2 with only U
    // learning the result, denoted RwdU (mnemonics for "Randomized
    // PwdU").

    // U generates an "envelope" EnvU defined as
    // EnvU = AuthEnc(RwdU; PrivU, PubU, PubS)

    // where AuthEnc is an authenticated encryption function with the
    // "key committing" property and is specified in Section 3.1.1 below.
    // In EnvU, all values require authentication and PrivU also requires
    // encryption.  However, for simplicity and to hide the EnvU
    // contents, we specify that all values are encrypted (not just
    // authenticated).  PubU can be omitted from EnvU if it is not needed
    // for running the key-exchange protocol by the client or if it can
    // be reconstructed from PrivU.

    // U sends EnvU and PubU to S and erases PwdU, RwdU and all keys.

    registration(8, 10);
}
