use opaque::registration;

use rand::rngs::OsRng;
use ed25519_dalek::Keypair;
use ed25519_dalek::PublicKey;


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
    blake::hash(256, b"password", &mut alpha).unwrap();

    // a cyclic group G of prime order q
    // -> G is the Ristretto group of prime order q


    // a generator g of G
    // -> g is something that can return a point from the group,
    // from the Ed25519 curve



    // a hash function H' mapping arbitrary strings into G
    // where H' is modeled as a random oracle
    // -> This is the hashing of a string to an elliptical
    // curve point.



    // DH-OPRF domain: any string
    // -> "plaintext"

    // DH-OPRF range: The range of the hash function H
    // -> what is the range of the blake2?


    // DH-OPRF key: A random element k in [0..q-1]; denote v=g^k
    // -> This is the key the server generates to feed the OPRF, I think


    // ***> Spec

    // Protocol for computing DH-OPRF, U with input x and S with input k:
    // o  U: choose random r in [0..q-1], send alpha=H'(x)*g^r to S
    // o  S: upon receiving a value alpha, respond with v=g^k and
    // beta=alpha^k
    // o  U: upon receiving values beta and v, set the PRF output to
    // H(x, v, beta*v^{-r})


    // ***> Impl

}

fn main() {
    println!("`~- OPAQUE -~'");

    // 3.1.  Password registration
    // https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-02#section-3.1
    // Password registration is run between a user U and a server S.

    // U chooses password PwdU and a pair of private-public keys PrivU
    // and PubU for the given protocol KE

    // CSPRING: just using OS's PRNG for now
    let mut csprng: OsRng = OsRng::new().unwrap();
    // Generate a keypair
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let _public_key: PublicKey = keypair.public;

    // basic password for now
    let _password = "fizzbangpopdog";
    let _user_id = 8;

    //  Protocol for computing DH-OPRF, U with input x and S with input k:
    //  U: choose random r in [0..q-1], send alpha=H'(x)*g^r to S
    let mut alpha = [0; 32];
    blake::hash(256, b"password", &mut alpha).unwrap();

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
