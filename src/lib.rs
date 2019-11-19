use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_os::OsRng;

use x25519_dalek::EphemeralSecret;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Clone)]
pub struct Envelope {
    pub priv_u: StaticSecret,
    pub pub_u: PublicKey,
    pub pub_s: PublicKey,
}

lazy_static! {
    static ref USER_MAP: Mutex<HashMap<String, Envelope>> =
        { Mutex::new(HashMap::new()) };
}

pub struct RegistrationResult {
    pub beta: RistrettoPoint,
    pub v: Scalar,
    pub pub_s: PublicKey,
}

pub struct AuthenticationResult {
    pub beta: RistrettoPoint,
    pub env_u: Envelope,
    pub v: Scalar,
}

pub fn registration_1(
    alpha: &RistrettoPoint,
    g: &Scalar,
) -> RegistrationResult {
    // Guard: Ensure alpha is in the Ristretto group

    // S chooses OPRF key kU (random and independent for each user U) and
    // sets vU = g^kU;

    // it also chooses its own pair of private-public
    // keys PrivS and PubS for use with protocol KE (the server can use
    // the same pair of keys with multiple users), and sends PubS to U.

    let mut cspring = OsRng::new().unwrap();
    let priv_s = EphemeralSecret::new(&mut cspring);
    let pub_s = PublicKey::from(&priv_s);

    // CSPRING: just using OS's PRNG for now
    //    let mut csprng: OsRng = OsRng::new().unwrap();
    // Generate a keypair
    //    let keypair: Keypair = Keypair::generate(&mut csprng);
    //    let _public_key: PublicKey = keypair.public;

    // S stores (EnvU, PubS, PrivS, PubU, kU, vU) in a user-specific
    // record.  If PrivS and PubS are used for multiple users, S can
    // store these values separately and omit them from the user's
    // record.

    // Note (salt).  We note that in OPAQUE the OPRF key acts as the secret
    // salt value that ensures the infeasibility of pre-computation attacks.
    // No extra salt value is needed.

    // Note (password rules).  The above procedure has the significant
    // advantage that the user's password is not disclosed to the server
    // even during registration.  Some sites require learning the user's
    // password for enforcing password rules.  Doing so voids this important
    // security property of OPAQUE and is not recommended.  Moving the
    // password check procedure to the client side is a more secure
    // alternative.

    let k = Scalar::random(&mut cspring);
    let v = g * k;
    let beta = alpha * k;
    RegistrationResult {
        beta: beta,
        pub_s: pub_s,
        v: v,
    }
}

pub fn registration_2(username: &str, envelope: Envelope) {
    USER_MAP
        .lock()
        .unwrap()
        .insert(username.to_string(), envelope);
    println!("Registering {:?}:", username);
}

pub fn authenticate_1(
    username: &str,
    alpha: &RistrettoPoint,
    g: &Scalar,
) -> AuthenticationResult {
    let mut cspring = OsRng::new().unwrap();
    let k = Scalar::random(&mut cspring);
    let v = g * k;
    let beta = alpha * k;

    let envelope: Envelope =
        USER_MAP.lock().unwrap().get(username).unwrap().clone();

    // S to C: beta=alpha^kU, vU, EnvU, KE2
    AuthenticationResult {
        beta: beta,
        env_u: envelope,
        v: v,
    }
}

/*pub fn authenticate_step_2(
*/

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
