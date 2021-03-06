use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm_siv::Aes256GcmSiv;
use crate::envelope::*;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Keypair, Signature};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_os::OsRng;
use sha2::Sha512;
use sha3::{Digest, Sha3_512};

use crate::key_exchange::KeyExchange;

type HmacSha512 = Hmac<Sha512>;

pub fn registration_start(
    password: &str,
) -> ([u8; 32], [u8; 64], [u8; 32], [u8; 32], [u8; 32]) {
    let mut cspring = OsRng::new().unwrap();
    let keypair: Keypair = Keypair::generate(&mut cspring);

    let priv_u = keypair.secret.to_bytes();
    let pub_u = keypair.public.to_bytes();

    let r = Scalar::random(&mut cspring);
    let hash_prime =
        RistrettoPoint::hash_from_bytes::<Sha3_512>(password.as_bytes());
    let alpha_point: RistrettoPoint = hash_prime * r;
    let alpha = alpha_point.compress().to_bytes();

    (alpha, keypair.to_bytes(), pub_u, priv_u, r.to_bytes())
}

pub fn registration_finalize(
    password: &str,
    beta: &[u8; 32],
    v: &[u8; 32],
    pub_u: &[u8; 32],
    pub_s: &[u8; 32],
    priv_u: &[u8; 32],
    r: &[u8; 32],
) -> Vec<u8> {
    let beta_point = CompressedRistretto::from_slice(&beta[..]);
    let beta = beta_point.decompress().unwrap();
    let v_point = CompressedRistretto::from_slice(&v[..]);
    let v = v_point.decompress().unwrap();

    let r = Scalar::from_canonical_bytes(*r).unwrap();

    let inverse_r = r.invert();
    let sub_beta = beta * inverse_r;

    let mut hasher = Sha3_512::new();
    // assuming multiple inputs create a unique hash not just concating,
    // verse serializing
    hasher.input(password.as_bytes());
    hasher.input(v.compress().as_bytes());
    hasher.input(sub_beta.compress().to_bytes());
    let rwd_u = hasher.result();

    let envelope = Envelope::new(pub_u, priv_u, pub_s).unwrap();
    envelope.encrypt(&rwd_u)
}

pub fn authenticate_start(
    _username: &str,
    password: &str,
) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    let mut cspring = OsRng::new().unwrap();

    let r = Scalar::random(&mut cspring);
    let hash_prime =
        RistrettoPoint::hash_from_bytes::<Sha3_512>(password.as_bytes());
    let alpha_point: RistrettoPoint = hash_prime * r;

    let x = Scalar::random(&mut cspring);
    let ke_1_point = RISTRETTO_BASEPOINT_POINT * x;

    let alpha = alpha_point.compress().to_bytes();
    let ke_1 = ke_1_point.compress().to_bytes();

    (alpha, ke_1, x.to_bytes(), r.to_bytes())
}

pub fn authenticate_finalize(
    password: &str,
    keypair: &[u8; 64],
    envelope: &Vec<u8>,
    beta: &[u8; 32],
    v: &[u8; 32],
    ke_2: &Vec<u8>,
    x: &[u8; 32],
    y: &[u8; 32],
    r: &[u8; 32],
) -> Vec<u8> {
    let beta_point = CompressedRistretto::from_slice(&beta[..]);
    let beta = beta_point.decompress().unwrap();

    let v_point = CompressedRistretto::from_slice(&v[..]);
    let v = v_point.decompress().unwrap();

    let y_point = CompressedRistretto::from_slice(&y[..]);
    let y = y_point.decompress().unwrap();

    // OPRF
    let keypair = Keypair::from_bytes(keypair).unwrap();

    // is_canonical
    let r = Scalar::from_canonical_bytes(*r).unwrap();

    let inverse_r = r.invert();
    let sub_beta = beta * inverse_r;

    let mut hasher = Sha3_512::new();
    hasher.input(password.as_bytes()); // NOTE: Harden with a key derivitive, Section 3.4
    hasher.input(v.compress().to_bytes());
    hasher.input(sub_beta.compress().to_bytes());
    let rwd_u = hasher.result();

    // Use rwd_u_a to decrypt envelope

    let hkdf = Hkdf::<Sha512>::new(None, &rwd_u);
    let mut okm = [0u8; 44]; // 32 byte key + 96 bit nonce
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap(); // make info the domain string, +
    hkdf.expand(&info, &mut okm).unwrap();

    let encryption_key: GenericArray<u8, typenum::U32> =
        GenericArray::clone_from_slice(&okm[0..32]);
    let aead = Aes256GcmSiv::new(encryption_key);
    let nonce: GenericArray<u8, typenum::U12> =
        GenericArray::clone_from_slice(&okm[32..44]);

    let _envelope_decrypted = aead
        .decrypt(&nonce, envelope.as_slice())
        .expect("decryption failure");

    // SIGMA

    //  KE3 = Sig(PrivU; g^y, g^x), Mac(Km2; IdU)
    // { A, SIGa(g^y, g^x), MAC(Km; A) } Ke

    // decrypt ke_2

    // #SECURITY: Prove that all scalars are non-zero, init and inverse
    let x = Scalar::from_canonical_bytes(*x).unwrap();
    let dh: RistrettoPoint = x * y;

    let hkdf = Hkdf::<Sha512>::new(None, dh.compress().as_bytes());
    let mut okm_dh = [0u8; 108]; // 32 byte key, 96 bit nonce, 64 bytes
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    hkdf.expand(&info, &mut okm_dh).unwrap();

    let encryption_key_dh: GenericArray<u8, typenum::U32> =
        GenericArray::clone_from_slice(&okm_dh[0..32]);
    let aead_dh = Aes256GcmSiv::new(encryption_key_dh);
    let nonce_dh: GenericArray<u8, typenum::U12> =
        GenericArray::clone_from_slice(&okm_dh[32..44]);

    let _key_2_decrypted = aead_dh
        .decrypt(&nonce_dh, ke_2.as_slice())
        .expect("decryption failure");

    // SIGa(g^y, g^x)
    let mut prehashed: Sha3_512 = Sha3_512::new();
    prehashed.input(y.compress().as_bytes());
    prehashed.input(ke_2);
    let context: &[u8] = b"SpecificCustomerDomainName";
    let sig: Signature = keypair.sign_prehashed(prehashed, Some(context));

    // MAC(Km; PubS)
    let mut mac = HmacSha512::new_varkey(&okm_dh[44..108]).unwrap();
    mac.input(&keypair.public.to_bytes());

    let key_exchange_3 = KeyExchange {
        identity: keypair.public.to_bytes(),
        signature: &sig.to_bytes(),
        mac: mac.result().code().as_slice().to_vec(),
    };

    let payload_dh: Vec<u8> = bincode::serialize(&key_exchange_3).unwrap();
    let encrypted_ke_3 =
        aead_dh.encrypt(&nonce_dh, payload_dh.as_slice()).unwrap();

    encrypted_ke_3
}
