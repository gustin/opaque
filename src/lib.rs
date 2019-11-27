use bincode::{deserialize, serialize};
use serde::{Deserialize, Serialize};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::RngCore;
use rand_os::OsRng;

use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature};

use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use aes_gcm_siv::Aes256GcmSiv;

use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::Mutex;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use sha3::{Digest, Sha3_512};

type HmacSha512 = Hmac<Sha512>;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Envelope {
    pub priv_u: [u8; 32],
    pub pub_u: [u8; 32],
    pub pub_s: [u8; 32],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyExchange<'a> {
    pub identity: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub signature: &'a [u8],
    #[serde(with = "serde_bytes")]
    pub mac: Vec<u8>,
    // nonce, sid, info
}

#[derive(Clone)]
struct UserRecord {
    envelope: Option<Vec<u8>>,
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
    println!("*) beta=alpha^kU, vU (g^k)");
    let k = Scalar::random(&mut cspring); // salt, private
    let v: RistrettoPoint = RISTRETTO_BASEPOINT_POINT * k; // salt 2, public
    let beta = alpha * k;
    let user_record = UserRecord {
        envelope: None,
        k_u: k,
        v_u: v,
    };
    println!("-) kU {:?}:", k);
    println!("-) vU {:?}:", v);
    println!("-) beta {:?}", beta);
    USER_MAP
        .lock()
        .unwrap()
        .insert(username.to_string(), user_record);

    (beta, v, keypair.public.to_bytes())
}

pub fn registration_2(username: &str, envelope: &Vec<u8>) {
    let mut user_record: UserRecord =
        USER_MAP.lock().unwrap().get(username).unwrap().clone();
    user_record.envelope = Some(envelope.to_vec());
    USER_MAP
        .lock()
        .unwrap()
        .insert(username.to_string(), user_record);
    println!("=) Registered {:?} with envelope {:?}:", username, envelope);
}

pub fn authenticate_1(
    username: &str,
    alpha: &RistrettoPoint,
    ke_1: &RistrettoPoint,
) -> (
    RistrettoPoint,
    RistrettoPoint,
    Vec<u8>,
    Vec<u8>,
    RistrettoPoint,
) {
    let user_record: UserRecord =
        USER_MAP.lock().unwrap().get(username).unwrap().clone();

    // S to C: beta=alpha^kU, vU, EnvU, KE2
    println!("*) beta=alpha^kU, vU (g^k)");
    let beta = alpha * user_record.k_u; // DH-OPRF paper recommends rotating
    println!("-) kU {:?}:", user_record.k_u);
    println!("-) vU {:?}:", user_record.v_u);
    println!("-) beta {:?}:", beta);

    //  SIGMA
    //  KE2 = g^y, Sig(PrivS; g^x, g^y), Mac(Km1; IdS)

    // sidA:
    // sidB
    // g^y
    // nB
    // infoB

    let ke_2: RistrettoPoint = RISTRETTO_BASEPOINT_POINT * user_record.k_u;
    let dh: RistrettoPoint = user_record.k_u * ke_1;

    let hkdf = Hkdf::<Sha512>::new(None, dh.compress().as_bytes());
    let mut okm = [0u8; 108]; // 32 byte key, 96 bit nonce, 64 bytes
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    hkdf.expand(&info, &mut okm).unwrap();

    let mut cspring = OsRng::new().unwrap();
    // Guard: Using ed25519 keys here for signing, x25519
    // may (or should be) more efficient for DH
    let keypair: Keypair = Keypair::generate(&mut cspring);
    let public_key = keypair.public.to_bytes();

    // MAC(Km; PubS)
    let mut mac = HmacSha512::new_varkey(&okm[44..108]).unwrap();
    mac.input(&public_key);

    // SIG(B; g^x, g^y)
    let mut prehashed: Sha3_512 = Sha3_512::new();
    prehashed.input(ke_1.compress().as_bytes());
    prehashed.input(ke_2.compress().as_bytes());
    let context: &[u8] = b"SpecificCustomerDomainName";
    let sig: Signature = keypair.sign_prehashed(prehashed, Some(context));

    println!("-) KE_2: {:?}", ke_2);
    println!("-) Shared Secret: {:?}", dh);
    // Guard: HMAC crate:
    // Be very careful using this method (code()), since incorrect use of the code
    // value may permit timing attacks which defeat the security provided by the Mac
    // trait.
    //    println!("-) MAC(Km; PubS): {:?}", mac.result().code());
    println!("-) SIG(PrivS; g^x, g^y): {:?}", sig);

    let key_exchange = KeyExchange {
        identity: public_key,
        signature: &sig.to_bytes(),
        mac: mac.result().code().as_slice().to_vec(),
    };

    let encryption_key: GenericArray<u8, typenum::U32> =
        GenericArray::clone_from_slice(&okm[0..32]);
    let aead = Aes256GcmSiv::new(encryption_key);
    let nonce: GenericArray<u8, typenum::U12> =
        GenericArray::clone_from_slice(&okm[32..44]);

    let payload: Vec<u8> = bincode::serialize(&key_exchange).unwrap();
    let encrypted_ke_2 = aead.encrypt(&nonce, payload.as_slice()).unwrap();

    println!("-) DH encryption key 32-byte {:?}:", encryption_key);
    println!("-) DH nonce 96 bit {:?}:", nonce);

    // sidA, sidB, g^y, nB, info1B
    // gy, {B, SigB(g^x, g^y), MAC(Km; B)} Ke
    //let message = ke_1 + ke_2;
    //    let sig = keypair.sign(message.to_bytes());

    // Mac(Km1; IdS)
    // Km1 must be computationally independent from the authentication key

    (
        beta,
        user_record.v_u,
        user_record.envelope.unwrap(),
        encrypted_ke_2,
        ke_2,
    )
}

pub fn authenticate_2(username: &str, ke_3: &RistrettoPoint) {
    println!("=) Verified KE3 -- {} logged in.", username);
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
