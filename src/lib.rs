use bincode::{serialize, deserialize};
use serde::{Serialize, Deserialize};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::RngCore;
use rand_os::OsRng;

use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature};

use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Serialize, Deserialize, Clone)]
pub struct Envelope {
    pub priv_u: [u8; 32],
    pub pub_u: [u8; 32],
    pub pub_s: [u8; 32],
}

#[derive(Clone)]
struct UserRecord {
    envelope: Option<Envelope>,
    k_u: Scalar,
    v_u: RistrettoPoint,
}

lazy_static! {
    static ref USER_MAP: Mutex<HashMap<String, UserRecord>> =
        { Mutex::new(HashMap::new()) };
}

pub fn registration_1(
    username: &str,
    alpha: &RistrettoPoint,
    ke_1: &RistrettoPoint,
) -> (RistrettoPoint, RistrettoPoint, [u8; 32]) {
    // Guard: Ensure alpha is in the Ristretto group

    // S chooses OPRF key kU (random and independent for each user U) and
    // sets vU = g^kU;

    // it also chooses its own pair of private-public
    // keys PrivS and PubS for use with protocol KE (the server can use
    // the same pair of keys with multiple users), and sends PubS to U.

    let mut cspring = OsRng::new().unwrap();
    let keypair: Keypair = Keypair::generate(&mut cspring);

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

    // S to C: beta=alpha^kU, vU (g^k), EnvU : KE2
    let k = Scalar::random(&mut cspring); // salt, private
    let v: RistrettoPoint = RISTRETTO_BASEPOINT_POINT * k; // salt 2, public
    let beta = alpha * k;
    let user_record = UserRecord {
        envelope: None,
        k_u: k,
        v_u: v,
    };
    USER_MAP
        .lock()
        .unwrap()
        .insert(username.to_string(), user_record);

    //  SIGMA
    //  KE2 = g^y, Sig(PrivS; g^x, g^y), Mac(Km1; IdS)
    let ke_2: RistrettoPoint = k * RISTRETTO_BASEPOINT_POINT;
    let message = ke_1 + ke_2;
    //    let sig = keypair.sign(message.to_bytes());

    // Mac(Km1; IdS)
    // Km1 must be computationally independent from the authentication key

    (beta, v, keypair.public.to_bytes())
}

pub fn registration_2(username: &str, envelope: Envelope) {
    let mut user_record: UserRecord =
        USER_MAP.lock().unwrap().get(username).unwrap().clone();
    user_record.envelope = Some(envelope);
    USER_MAP
        .lock()
        .unwrap()
        .insert(username.to_string(), user_record);
    println!("Registering {:?}:", username);
}

pub fn authenticate_1(
    username: &str,
    alpha: &RistrettoPoint,
) -> (RistrettoPoint, RistrettoPoint, Envelope) {
    let user_record: UserRecord =
        USER_MAP.lock().unwrap().get(username).unwrap().clone();

    // S to C: beta=alpha^kU, vU, EnvU, KE2
    let beta = alpha * user_record.k_u;

    (beta, user_record.v_u, user_record.envelope.unwrap())
}

pub fn authenticate_step_2(username: &str) {}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
