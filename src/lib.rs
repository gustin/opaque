pub mod client;
pub mod sigma;

use crate::sigma::KeyExchange;

use serde::{Deserialize, Serialize};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

use rand_os::OsRng;

use ed25519_dalek::{Keypair, PublicKey, Signature};

use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm_siv::Aes256GcmSiv;

use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::Mutex;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha512; // NOTE: Drop sha2/sha3 to Blake for performance
use sha3::{Digest, Sha3_512};

pub type HmacSha512 = Hmac<Sha512>;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Envelope {
    pub priv_u: [u8; 32],
    pub pub_u: [u8; 32],
    pub pub_s: [u8; 32],
}

#[derive(Clone)]
struct UserRecord {
    envelope: Option<Vec<u8>>,
    pub_u: Option<[u8; 32]>,
    k_u: Scalar,
    v_u: RistrettoPoint,
}

lazy_static! {
    static ref USER_MAP: Mutex<HashMap<String, UserRecord>> =
        { Mutex::new(HashMap::new()) };
}

pub fn registration_start(
    username: &str,
    alpha: &[u8; 32],
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    println!("=> Rusty Registration Start");
    println!("Alpha: {:?}", alpha);
    let alpha_point = CompressedRistretto::from_slice(&alpha[..]);
    let alpha = alpha_point.decompress().unwrap();

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
        pub_u: None,
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

    (
        beta.compress().to_bytes(),
        v.compress().to_bytes(),
        keypair.public.to_bytes(),
    )
}

pub fn registration_finalize(
    username: &str,
    pub_u: &[u8; 32],
    envelope: &Vec<u8>,
) {
    println!("=> Rusty Registration Finalize");
    println!("PubU: {:?}", pub_u);
    println!("Envelope: {:?}", envelope);
    let mut user_record =
        USER_MAP.lock().unwrap().get(username).unwrap().clone();
    user_record.envelope = Some(envelope.to_vec());

    user_record.pub_u = Some(*pub_u);
    USER_MAP
        .lock()
        .unwrap()
        .insert(username.to_string(), user_record);
    println!("=) Registered {:?} with envelope {:?}:", username, envelope);
}

pub fn authenticate_start(
    username: &str,
    alpha: &[u8; 32],
    ke_1: &[u8; 32],
) -> ([u8; 32], [u8; 32], Vec<u8>, Vec<u8>, [u8; 32]) {
    println!("====> Rusty Authentication Start");
    println!("Alpha: {:?}", alpha);
    println!("KE 1: {:?}", ke_1);
    let alpha_point = CompressedRistretto::from_slice(&alpha[..]);
    let alpha = alpha_point.decompress().unwrap();

    let ke_1_point = CompressedRistretto::from_slice(&ke_1[..]);
    let ke_1 = ke_1_point.decompress().unwrap();

    let user_record: UserRecord =
        USER_MAP.lock().unwrap().get(username).unwrap().clone();

    // S to C: beta=alpha^kU, vU, EnvU, KE2
    println!("*) beta=alpha^kU, vU (g^k)");
    let beta = alpha * user_record.k_u; // DH-OPRF paper recommends rotating
    println!("-) kU {:?}:", user_record.k_u);
    println!("-) vU {:?}:", user_record.v_u);
    println!("-> Envelope {:?}:", user_record.envelope);
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
        beta.compress().to_bytes(),
        user_record.v_u.compress().to_bytes(),
        user_record.envelope.unwrap(),
        encrypted_ke_2,
        ke_2.compress().to_bytes(),
    )
}

// NOTE: Think about gaming this function independent of authenticate_start
pub fn authenticate_finalize(username: &str, ke_3: &Vec<u8>, x: &[u8; 32]) {
    println!("=> Rusty Authenticate Finalize");
    println!("Key 3: {:?}:", ke_3);
    println!("X: {:?}:", x);
    let x_point = CompressedRistretto::from_slice(&x[..]);
    let x = x_point.decompress().unwrap();

    let user_record: UserRecord =
        USER_MAP.lock().unwrap().get(username).unwrap().clone();

    let ke_2: RistrettoPoint = RISTRETTO_BASEPOINT_POINT * user_record.k_u;
    let dh: RistrettoPoint = user_record.k_u * x;

    let hkdf = Hkdf::<Sha512>::new(None, dh.compress().as_bytes());
    let mut okm_dh = [0u8; 108]; // 32 byte key, 96 bit nonce, 64 bytes
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    hkdf.expand(&info, &mut okm_dh).unwrap();

    println!("-) HKDF OKM {}", hex::encode(&okm_dh[..]));

    let encryption_key_dh: GenericArray<u8, typenum::U32> =
        GenericArray::clone_from_slice(&okm_dh[0..32]);
    let aead_dh = Aes256GcmSiv::new(encryption_key_dh);
    let nonce_dh: GenericArray<u8, typenum::U12> =
        GenericArray::clone_from_slice(&okm_dh[32..44]);

    println!("Encryption Key DH: {:?}", encryption_key_dh);
    println!("Nonce DH: {:?}", nonce_dh);
    println!("KE 3 Slice: {:?}", ke_3.as_slice());
    println!("Key 3 Size: {}", ke_3.capacity());
    let key_3_decrypted = aead_dh
        .decrypt(&nonce_dh, ke_3.as_slice())
        .expect("decryption failure");
    let key_3_for_realz: KeyExchange =
        bincode::deserialize(key_3_decrypted.as_slice()).unwrap();

    let pub_u = PublicKey::from_bytes(&key_3_for_realz.identity).unwrap();

    let mut prehashed: Sha3_512 = Sha3_512::new();
    prehashed.input(ke_2.compress().as_bytes());
    prehashed.input(x.compress().as_bytes());
    let context: &[u8] = b"SpecificCustomerDomainName";
    let signature: Signature =
        Signature::from_bytes(&key_3_for_realz.signature).unwrap();
    let verified = pub_u.verify_prehashed::<Sha3_512>(
        prehashed,
        Some(context),
        &signature,
    );

    // check Mac on A

    println!("=) {:?}", verified.unwrap());

    println!("=) Signature Verified KE3 -- {} logged in.", username);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration() {
        let username = "jerryg";
        let alpha: [u8; 32] = [
            226, 35, 157, 8, 63, 97, 171, 99, 69, 189, 159, 141, 180, 4, 203,
            46, 116, 119, 130, 203, 210, 2, 185, 200, 136, 149, 83, 102, 196,
            13, 109, 9,
        ];
        let (beta, v, pub_s) = registration_start(&username, &alpha);

        let pub_u: [u8; 32] = [
            205, 174, 154, 148, 138, 21, 142, 98, 102, 212, 171, 21, 75, 131,
            129, 188, 131, 83, 38, 74, 55, 0, 75, 190, 50, 189, 47, 107, 235,
            246, 92, 85,
        ];

        let envelope: [u8; 112] = [
            196, 242, 45, 186, 240, 196, 70, 205, 94, 21, 77, 237, 22, 49, 251,
            73, 174, 210, 200, 194, 199, 169, 89, 211, 131, 55, 55, 80, 178,
            174, 75, 231, 17, 64, 84, 25, 177, 110, 23, 17, 220, 32, 161, 243,
            76, 170, 71, 66, 131, 240, 105, 32, 111, 74, 127, 232, 180, 92,
            204, 103, 155, 190, 247, 249, 93, 139, 23, 179, 39, 229, 170, 14,
            5, 25, 250, 104, 164, 144, 187, 174, 68, 211, 10, 70, 232, 25, 157,
            177, 236, 219, 119, 119, 14, 80, 52, 106, 147, 182, 58, 108, 183,
            116, 183, 37, 71, 252, 47, 84, 237, 223, 76, 115,
        ];
        registration_finalize(&username, &pub_u, &envelope.to_vec());
    }

    #[test]
    fn authentication() {
        let username = "jerryg";
        let alpha: [u8; 32] = [
            142, 135, 61, 248, 178, 203, 86, 140, 221, 69, 98, 1, 123, 239,
            208, 228, 127, 152, 164, 171, 25, 254, 202, 205, 243, 174, 229,
            245, 118, 46, 39, 14,
        ];
        let key: [u8; 32] = [
            182, 211, 247, 22, 251, 171, 209, 121, 26, 41, 7, 0, 202, 103, 82,
            151, 112, 232, 227, 123, 91, 177, 83, 137, 81, 203, 176, 202, 69,
            76, 129, 96,
        ];
        let (bete, v, envelope, key, y) =
            authenticate_start(&username, &alpha, &key);

        let key: [u8; 192] = [
            118, 42, 51, 187, 226, 136, 108, 19, 178, 151, 29, 197, 229, 153,
            204, 173, 28, 212, 54, 214, 121, 92, 101, 54, 133, 124, 118, 122,
            185, 11, 202, 191, 176, 148, 177, 154, 154, 233, 131, 18, 12, 137,
            35, 224, 14, 120, 242, 106, 165, 133, 208, 196, 131, 70, 39, 65,
            103, 76, 29, 23, 128, 206, 153, 45, 23, 48, 232, 174, 83, 97, 191,
            52, 53, 39, 59, 95, 138, 132, 26, 22, 171, 153, 240, 52, 213, 106,
            192, 54, 181, 32, 41, 170, 134, 53, 84, 239, 98, 36, 58, 175, 140,
            170, 123, 168, 186, 171, 143, 172, 7, 184, 18, 104, 30, 103, 31,
            44, 188, 234, 137, 202, 115, 35, 239, 79, 43, 226, 54, 20, 75, 33,
            183, 205, 130, 95, 255, 56, 196, 27, 70, 144, 202, 250, 150, 149,
            132, 89, 105, 118, 29, 15, 16, 131, 40, 135, 45, 99, 163, 155, 188,
            81, 215, 43, 74, 87, 23, 84, 55, 248, 26, 61, 203, 162, 221, 10,
            31, 108, 228, 48, 171, 168, 207, 196, 39, 47, 173, 100, 167, 166,
            236, 151, 164, 193,
        ];
        let x: [u8; 32] = [
            182, 211, 247, 22, 251, 171, 209, 121, 26, 41, 7, 0, 202, 103, 82,
            151, 112, 232, 227, 123, 91, 177, 83, 137, 81, 203, 176, 202, 69,
            76, 129, 96,
        ];
        authenticate_finalize(&username, &key.to_vec(), &x);
    }
}
