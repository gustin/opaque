
use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead, Payload};
use aes_gcm_siv::Aes256GcmSiv;
use bincode::{deserialize, serialize};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Keypair, Signature};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_os::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use sha3::{Digest, Sha3_512};

type HmacSha512 = Hmac<512>;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Envelope {
    pub priv_u: [u8; 32],
    pub pub_u: [u8; 32],
    pub pub_s: [u8; 32],
}

pub fn registration_start(password: &str) -> ([u8; 32], [u8; 32], [u8; 32]) {
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

pub fn registration_finalize(
    password: &str,
    beta: &[u8; 32],
    v: &[u8; 32],
    pub_u: &[u8; 32],
    pub_s: &[u8; 32],
    priv_u: &[u8; 32],
) -> (Vec<u8>) {
    let beta_point = CompressedRistretto::from_slice(&beta[..]);
    let beta = beta_point.decompress().unwrap();
    let v_point = CompressedRistretto::from_slice(&v[..]);
    let v = v_point.decompress().unwrap();

    // NOTE: R should be shared with registration start
    let mut cspring = OsRng::new().unwrap();
    let r = Scalar::random(&mut cspring);

    let inverse_r = r.invert();
    let sub_beta = beta * inverse_r;

    let mut hasher = Sha3_512::new();
    // assuming multiple inputs create a unique hash not just concating,
    // verse serializing
    hasher.input(password.as_bytes());
    hasher.input(v.compress().as_bytes());
    hasher.input(sub_beta.compress().to_bytes());
    let rwd_u = hasher.result();

    let envelope = Envelope {
        priv_u: *priv_u,
        pub_u: *pub_u,
        pub_s: *pub_s,
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

    env_cipher
}

pub fn authenticate_start(
    username: &str,
    password: &str,
) -> ([u8; 32], [u8; 32]) {
    let mut cspring = OsRng::new().unwrap();
    let keypair: Keypair = Keypair::generate(&mut cspring);

    let priv_u = keypair.secret.to_bytes();
    let pub_u = keypair.public.to_bytes();

    let r_a = Scalar::random(&mut cspring);
    let hash_prime_a =
        RistrettoPoint::hash_from_bytes::<Sha3_512>(password.as_bytes());
    let alpha_point: RistrettoPoint = hash_prime_a * r_a;

    let x = Scalar::random(&mut cspring);
    let ke_1_point = RISTRETTO_BASEPOINT_POINT * x;

    let alpha = alpha_point.compress().to_bytes();
    let ke_1 = ke_1_point.compress().to_bytes();

    (alpha, ke_1)
}

pub fn authenticate_finalize(
    password: &str,
    pub_u: &[u8; 32],
    envelope: &Vec<u8>,
    beta: &[u8; 32],
    v: &[u8; 32],
    ke_2: &Vec<u8>,
    &y: &[u8; 32],
) -> (Vec<u8>, [u8; 32]) {
    let beta_point = CompressedRistretto::from_slice(&beta[..]);
    let beta_a = beta_point.decompress().unwrap();

    let v_point = CompressedRistretto::from_slice(&v[..]);
    let v_a = v_point.decompress().unwrap();

    let y_point = CompressedRistretto::from_slice(&y[..]);
    let y = y_point.decompress().unwrap();

    // OPRF
    let mut cspring = OsRng::new().unwrap();
    let r_a = Scalar::random(&mut cspring);

    let inverse_r_a = r_a.invert();
    let sub_beta_a = beta_a * inverse_r_a;

    let mut hasher_a = Sha3_512::new();
    hasher_a.input(password.as_bytes()); // NOTE: Harden with a key derivitive, Section 3.4
    hasher_a.input(v.compress().to_bytes());
    hasher_a.input(sub_beta_a.compress().to_bytes());
    let rwd_u_a = hasher_a.result();

    // Use rwd_u_a to decrypt envelope

    let hkdf_a = Hkdf::<Sha512>::new(None, &rwd_u_a);
    let mut okm_a = [0u8; 44]; // 32 byte key + 96 bit nonce
    let info_a = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap(); // make info the domain string, +
    hkdf_a.expand(&info_a, &mut okm_a).unwrap();

    let encryption_key_a: GenericArray<u8, typenum::U32> =
        GenericArray::clone_from_slice(&okm_a[0..32]);
    let aead = Aes256GcmSiv::new(encryption_key_a);
    let nonce_a: GenericArray<u8, typenum::U12> =
        GenericArray::clone_from_slice(&okm_a[32..44]);

    let envelope_decrypted = aead
        .decrypt(&nonce_a, result.envelope.as_slice())
        .expect("decryption failure");
    let envelope_for_realz: Envelope =
        bincode::deserialize(envelope_decrypted.as_slice()).unwrap();

    // SIGMA

    //  KE3 = Sig(PrivU; g^y, g^x), Mac(Km2; IdU)
    // { A, SIGa(g^y, g^x), MAC(Km; A) } Ke

    // decrypt ke_2
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

    let key_2_decrypted = aead_dh
        .decrypt(&nonce_dh, result.key.as_slice())
        .expect("decryption failure");
    let key_2_for_realz: KeyExchange =
        bincode::deserialize(key_2_decrypted.as_slice()).unwrap();

    // SIGa(g^y, g^x)
    let mut prehashed: Sha3_512 = Sha3_512::new();
    prehashed.input(y.compress().as_bytes());
    prehashed.input(ke_1);
    let context: &[u8] = b"SpecificCustomerDomainName";
    let sig: Signature = keypair.sign_prehashed(prehashed, Some(context));

    // MAC(Km; PubS)
    let mut mac = HmacSha512::new_varkey(&okm_dh[44..108]).unwrap();
    mac.input(&pub_u);

    let key_exchange_3 = KeyExchange {
        identity: pub_u,
        signature: &sig.to_bytes(),
        mac: mac.result().code().as_slice().to_vec(),
    };

    let payload_dh: Vec<u8> = bincode::serialize(&key_exchange_3).unwrap();
    let encrypted_ke_3 =
        aead_dh.encrypt(&nonce_dh, payload_dh.as_slice()).unwrap();

    (encrypted_ke_3, &ke_1.compress().as_bytes())
}
