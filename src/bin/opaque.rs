use opaque::registration;

use rand::rngs::osrng;
use ed25519_dalek::keypair;
use ed25519_dalek::publickey;

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
