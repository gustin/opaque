use opaque::registration;

use rand::rngs::OsRng;
use ed25519_dalek::Keypair;
use ed25519_dalek::PublicKey;

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

    // take password and a cryptographic generator as inputs to hash function
    // results in a cryptographic point in a public-key group known as Alpha


    registration(8, 10);
}
