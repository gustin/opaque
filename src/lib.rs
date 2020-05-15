pub mod client;
pub mod envelope;
mod key_exchange;
pub mod sigma;

use crate::sigma::KeyExchange;

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
        .expect("decryption failure, authorization failed");
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
    fn register_and_authenticate() {
        let username = "jerryg";
        let alpha: [u8; 32] = [
            108, 205, 75, 42, 225, 170, 25, 15, 62, 90, 122, 155, 240, 155,
            225, 131, 110, 168, 70, 25, 251, 143, 69, 92, 254, 227, 213, 121,
            165, 35, 195, 29,
        ];
        let (_beta, _v, _pub_s) = registration_start(&username, &alpha);

        let pub_u: [u8; 32] = [
            207, 22, 253, 11, 52, 222, 99, 90, 81, 190, 238, 194, 251, 75, 74,
            2, 16, 68, 164, 9, 40, 186, 224, 222, 166, 173, 192, 76, 53, 86,
            179, 168,
        ];

        let envelope: [u8; 112] = [
            190, 34, 241, 150, 92, 165, 105, 175, 203, 74, 47, 126, 227, 252,
            3, 129, 68, 56, 16, 172, 107, 199, 253, 60, 9, 226, 1, 159, 124,
            249, 242, 158, 246, 44, 59, 145, 1, 181, 237, 56, 210, 19, 100, 94,
            128, 12, 253, 164, 41, 237, 190, 184, 9, 120, 85, 205, 53, 166, 97,
            68, 137, 77, 174, 45, 249, 77, 175, 59, 143, 31, 14, 12, 111, 159,
            6, 77, 154, 212, 80, 149, 99, 190, 191, 241, 16, 171, 226, 210, 42,
            140, 26, 39, 193, 197, 31, 251, 56, 51, 151, 52, 236, 126, 66, 232,
            191, 57, 69, 94, 53, 5, 163, 119,
        ];
        registration_finalize(&username, &pub_u, &envelope.to_vec());

        let alpha: [u8; 32] = [
            30, 200, 124, 246, 19, 85, 165, 91, 95, 234, 214, 93, 109, 14, 39,
            114, 185, 129, 141, 141, 7, 234, 47, 147, 219, 183, 145, 117, 9,
            116, 166, 49,
        ];
        let key: [u8; 32] = [
            72, 79, 202, 45, 141, 212, 156, 96, 121, 69, 228, 3, 178, 12, 144,
            236, 246, 53, 133, 85, 149, 25, 244, 215, 69, 178, 20, 242, 112,
            154, 116, 41,
        ];
        let (_beta, _v, _envelope, _key, _y) =
            authenticate_start(&username, &alpha, &key);

        let key: [u8; 192] = [
            54, 38, 180, 145, 237, 254, 52, 29, 136, 159, 110, 227, 159, 156,
            188, 54, 70, 43, 111, 115, 25, 220, 33, 164, 92, 15, 222, 159, 100,
            61, 22, 15, 177, 47, 28, 86, 157, 27, 13, 20, 111, 208, 198, 106,
            94, 206, 236, 7, 253, 186, 85, 246, 206, 87, 169, 123, 138, 202,
            59, 241, 204, 32, 69, 126, 65, 170, 247, 83, 248, 16, 248, 172, 74,
            19, 52, 56, 48, 224, 106, 68, 163, 200, 228, 76, 138, 91, 132, 8,
            223, 218, 221, 192, 46, 200, 183, 190, 17, 72, 102, 177, 218, 62,
            255, 229, 102, 221, 60, 14, 125, 164, 225, 89, 156, 25, 82, 49,
            147, 142, 60, 26, 27, 10, 81, 206, 255, 93, 182, 214, 159, 252,
            135, 241, 201, 30, 101, 157, 80, 51, 231, 166, 82, 133, 209, 1,
            250, 131, 7, 135, 245, 126, 197, 111, 141, 68, 244, 220, 202, 199,
            0, 216, 203, 17, 0, 202, 34, 3, 140, 204, 131, 61, 34, 193, 74, 52,
            148, 70, 92, 123, 201, 39, 35, 149, 173, 119, 63, 230, 108, 122,
            158, 88, 19, 78,
        ];
        let x: [u8; 32] = [
            72, 79, 202, 45, 141, 212, 156, 96, 121, 69, 228, 3, 178, 12, 144,
            236, 246, 53, 133, 85, 149, 25, 244, 215, 69, 178, 20, 242, 112,
            154, 116, 41,
        ];
        authenticate_finalize(&username, &key.to_vec(), &x);
    }
}
