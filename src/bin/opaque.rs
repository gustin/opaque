use opaque::*;

use rand_os::OsRng;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use aes_gcm_siv::Aes256GcmSiv;

// Warning: No security audits of the AES-GCM-Siv crate have ever been performed,
// and it has not been thoroughly assessed to ensure its operation is
// constant-time on common CPU architectures.

// Where possible the implementation uses constant-time hardware intrinsics,
// or otherwise falls back to an implementation which contains no
// secret-dependent branches or table lookups, however it's possible LLVM
// may insert such operations in certain scenarios.

// When targeting modern x86/x86_64 CPUs, use RUSTFLAGS to take advantage
// of high performance AES-NI and CLMUL CPU intrinsics

use hkdf::Hkdf;
use sha2::Sha512;
use sha3::{Digest, Sha3_512};

use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature};

fn OPRF(alpha: &RistrettoPoint, g: &RistrettoPoint) -> RistrettoPoint {
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
    //    let mut cspring: OsRng = OsRng::new().unwrap();
    //    let px = RistrettoPoint::random(&mut cspring);
    //    println!("RistrettoPoint::random(): {:?}", px);

    // a hash function H' mapping arbitrary strings into G
    // where H' is modeled as a random oracle
    // -> This is the hashing of a string to an elliptical
    // curve point.
    // RistrettoPoint::from_hash()
    //   let msg = "plaintext";
    //    let hash_prime = RistrettoPoint::hash_from_bytes::<>(msg.as_bytes());
    //    println!("Ristretto Point from hash prime function: {:?}", hash_prime);

    // DH-OPRF domain: any string
    // -> "plaintext"
    let domain = "plaintext";

    // DH-OPRF range: The range of the hash function H
    // -> what is the range of the blake2? is it 512? 2^512

    // DH-OPRF key: A random element k in [0..q-1]; denote v=g^k
    // -> This is the key the server generates to feed the OPRF.
    // The salt, v is the DH in the DH-OPRF

    // ***> Spec

    // Protocol for computing DH-OPRF, U with input x and S with input k:
    // o  U: choose random r in [0..q-1], send alpha=H'(x)*g^r to S
    // o  S: upon receiving a value alpha, respond with v=g^k and
    // beta=alpha^k
    // o  U: upon receiving values beta and v, set the PRF output to
    // H(x, v, beta*v^{-r})

    // ***> Impl

    // S: upon receiving a value alpha, respond with v=g^k and
    // beta=alpha^k
    let mut cspring = OsRng::new().unwrap();
    let k = Scalar::random(&mut cspring);
    let v = g * k;
    let beta = alpha * k;
    return beta;

    // alpha=(H'(x))^r in the first message and set the
    // function output to H(x,v,beta^{1/r})
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

    Alice's private key, a: 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
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

    /*let mut cspring = OsRng::new().unwrap();
    let alice_secret = EphemeralSecret::new(&mut cspring);
    let alice_public = PublicKey::from(&alice_secret);

    let bob_secret = EphemeralSecret::new(&mut cspring);
    let bob_public = PublicKey::from(&bob_secret);

    let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);
    let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);
    println!("Alice's Shared: {:?}", alice_shared_secret.as_bytes());
    println!("Bob's Shared: {:?}", bob_shared_secret.as_bytes());*/
}

fn main() {
    println!("`~- OPAQUE -~'");

    // ***> Spec

    // 3.1.  Password registration
    // https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-02#section-3.1
    // Password registration is run between a user U and a server S.

    // User / Client

    // U chooses password PwdU and a pair of private-public keys PrivU
    // and PubU for the given protocol KE

    // CSPRING: just using OS's PRNG for now
    let mut cspring = OsRng::new().unwrap();
    let keypair: Keypair = Keypair::generate(&mut cspring);

    let priv_u = keypair.secret.to_bytes();
    let pub_u = keypair.public;

    // basic password for now
    let username = "barry";
    let pwd_u = "fizzbangpopdog";

    //  Protocol for computing DH-OPRF, U with input x and S with input k:
    //  U: choose random r in [0..q-1], send alpha=H'(x)*g^r to S

    // The simplified form with the base point factor dropped:
    // spec: alpha=(H'(x))^r in the first message and set the
    //      function output to H(x,v,beta^{1/r})
    let r = Scalar::random(&mut cspring);
    let hash_prime =
        RistrettoPoint::hash_from_bytes::<Sha3_512>(pwd_u.as_bytes());
    let alpha: RistrettoPoint = hash_prime * r;
    // Guard: alpha should be authenticated when sent
    println!("Alpha {:?}:", alpha);

    // SIGMA-I
    // KE1 = g^x - X25519(a, 9) where 9 is the u-coordinate of the base
    // point and is encoded as a byte with value 9, followed by 31 zero bytes.
    let x = Scalar::random(&mut cspring);
    let ke_1 = x * RISTRETTO_BASEPOINT_POINT;
    let (beta, v, pub_s) = registration_1(username, &alpha, &ke_1);
    println!("Result beta: {:?} ", beta);
    println!("Result V: {:?} ", v);

    // Guard: Ensure v and beta are in the Group

    // U: upon receiving values beta and v, set the PRF output to
    // H(x, v, beta*v^{-r})

    // simplified:
    //  set the function output to H(x,v,beta^{1/r})

    let inverse_r = r.invert();
    let sub_beta = beta * inverse_r;

    // serialize then hash:
    // https://jameshfisher.com/2018/01/09/how-to-hash-multiple-values/
    // attack with non-injectivity of concatenation:
    // https://sakurity.com/blog/2015/05/08/pusher.html

    // U and S run OPRF(kU;PwdU) as defined in Section 2 with only U
    // learning the result, denoted RwdU (mnemonics for "Randomized
    // PwdU").

    let mut hasher = Sha3_512::new();
    hasher.input(r.to_bytes());
    hasher.input(v.compress().to_bytes());
    hasher.input(sub_beta.compress().to_bytes());
    let rwd_u = hasher.result();

    println!("Rwd U: {:?}:", rwd_u);

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

    // Encrypt-then-HMAC: Implement the AuthEnc scheme using any
    // encryption function in encrypt-then-pad-then-MAC mode where the
    // MAC is implemented with HMAC with a tag size of at least 256 bits (HMAC
    // ensures robustness through the collision-resistant property of the
    // underlying hash function).  This requires two separate keys, one for
    // encryption and one for HMAC, which can be derived from RwdU using,
    // for example, the HKDF-Expand function from [RFC5869].

    // Encrypt-then-Mac: https://tools.ietf.org/html/rfc7
    // https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-algorithms

    let envelope = Envelope {
        priv_u: priv_u,
        pub_u: pub_u,
        pub_s: pub_s,
    };

    // HMAC-based Extract-and-Expand:https://tools.ietf.org/html/rfc5869
    let hkdf = Hkdf::<Sha512>::new(None, &rwd_u);
    let mut output_key_material = [0u8; 44];
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    hkdf.expand(&info, &mut output_key_material).unwrap();

    println!("OKM is {}", hex::encode(&output_key_material[..]));

    // AES-GCM-SIV

    let encryption_key: GenericArray<u8, typenum::U32> =
        GenericArray::clone_from_slice(&output_key_material[0..32]);
    let aead = Aes256GcmSiv::new(encryption_key);
    let nonce: GenericArray<u8, typenum::U12> =
        GenericArray::clone_from_slice(&output_key_material[32..44]);
    //    let ciphertext = aead.encrypt(nonce, enveloper


    //println!("Cipher Envelope {:?} :", ciphertext);*/

    // Section 3.1.1 Implementing the EnvU envelop

    // U sends EnvU and PubU to S and erases PwdU, RwdU and all keys.
    registration_2(username, envelope);

    // C to S: Uid, alpha=H'(PwdU)*g^r, KE1

    let r_a = Scalar::random(&mut cspring);
    let hash_prime_a =
        RistrettoPoint::hash_from_bytes::<Sha3_512>(pwd_u.as_bytes());
    let alpha_a: RistrettoPoint = hash_prime * r;

    // S to C: beta=alpha^kU, vU, EnvU, KE2
    let (beta_a, v_a, envelope_a) = authenticate_1(username, &alpha_a);

    // determine RwD
    // decrypt EnvU using Rwd to obtain PrivU, PubU, PubS

    let inverse_r_a = r_a.invert();
    let sub_beta_a = beta_a * inverse_r_a;

    let mut hasher_a = Sha3_512::new();
    hasher_a.input(r.to_bytes());
    hasher_a.input(v.compress().to_bytes());
    hasher_a.input(sub_beta.compress().to_bytes());
    let rwd_u_a = hasher_a.result();

    println!("Rwd Authentication {:?}:", rwd_u_a);

    // run the specified KE protocol using their respective public and
    // private keys

    // For the authenticated variant, the same computations are done; but Alice
    // and Bob also own asymmetric key pairs usable for digital signatures, and
    // they use them: Alice signs whatever she sends to Bob, and Bob verifies that
    // signature (using Alice's public key). Similarly, Bob signs what he sends to
    // Alice, and Alice verifies that signature (using Bob's public key).

    /*
       o  C to S: Uid, alpha=H'(PwdU)*g^r, KE1
       o  S to C: beta=alpha^kU, vU, EnvU, KE2
       o  C to S: KE3
    */
    /*
    SIGMA-I can be represented schematically as follows:
        o  KE1 = g^x
        o  KE2 = g^y, Sig(PrivS; g^x, g^y), Mac(Km1; IdS)
        o  KE3 = Sig(PrivU; g^y, g^x), Mac(Km2; IdU)
        In this case, the private keys of user and server are signature keys.
        Key derivation is based on the DH value g^xy.
    */
}
