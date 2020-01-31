/*
 * Copyright 2019 Plaintext, LLC - All Rights Reserved
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited.
 * Proprietary and confidential.
 * */

use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use aes_gcm_siv::Aes256GcmSiv;
use bincode::{deserialize, serialize};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Keypair, Signature};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use opaque::sigma::KeyExchange;
use opaque::*;
use rand_os::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use sha3::{Digest, Sha3_512};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Envelope {
    pub priv_u: [u8; 32],
    pub pub_u: [u8; 32],
    pub pub_s: [u8; 32],
}

pub fn registration_start(password: String)
-> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut cspring = OsRng::new().unwrap();
    let keypair: Keypair = Keypair::generate(&mut cspring);

    let priv_u = keypair.secret.to_bytes();
    let pub_u = keypair.public.to_bytes();

    let r = Scalar::random(&mut cspring);
    let hash_prime =
        RistrettoPoint::hash_from_bytes::<Sha3_512>(password.as_bytes());
    let alpha_point: RistrettoPoint = hash_prime * r;
    let alpha = alpha_point.compress().to_bytes();

    (alpha, pub_u, priv_u)
}

pub fn registration_finalize(beta: &[u8; 32], v: &[u8; 32],
                             password: String,
                             pub_u: &[u8; 32], priv_u: &[u8;32])
-> ([u8; 32], Vec<u8>)
{
    let beta_point = CompressedRistretto::from_slice(&beta[..]);
    let beta = beta_point.decompress().unwrap();
    let v_point = CompressedRistretto::from_slice(&v[..]);
    let v = v_point.decompress().unwrap();

    let inverse_r = r.invert();
    let sub_beta = beta * inverse_r;

    let mut hasher = Sha3_512::new();
    // assuming multiple inputs create a unique hash not just concating,
    // verse serializing
    hasher.input(password.as_bytes());
    hasher.input(v.compress().as_bytes());
    hasher.input(sub_beta.compress().to_bytes());
    let rwd_u = hasher.result();

    // => Registration 2

    let envelope = Envelope {
        priv_u: priv_u,
        pub_u: pub_u,
        pub_s: pub_s,
    };

    let hkdf = Hkdf::<Sha512>::new(None, &rwd_u);
    let mut output_key_material = [0u8; 44]; // 32 byte key + 96 bit nonce
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap(); // NOTE: check info value
    hkdf.expand(&info, &mut output_key_material).unwrap();

    let encryption_key: GenericArray<u8, typenum::U32> =
        GenericArray::clone_from_slice(&output_key_material[0..32]);
    let aead = Aes256GcmSiv::new(encryption_key);
    let nonce: GenericArray<u8, typenum::U12> =
        GenericArray::clone_from_slice(&output_key_material[32..44]);

    let payload: Vec<u8> = bincode::serialize(&envelope).unwrap();
    let env_cipher = aead.encrypt(&nonce, payload.as_slice()).unwrap();

    (pub_u, env_cipher)
}


