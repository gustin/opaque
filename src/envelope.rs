use crate::key_exchange::PUBLIC_KEY_SIZE;
use crate::key_exchange::SECRET_KEY_SIZE;
use serde::{Deserialize, Serialize};

use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm_siv::Aes256GcmSiv;

use hkdf::Hkdf;
use sha2::Sha512;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Envelope {
    pub pub_u: [u8; PUBLIC_KEY_SIZE],
    pub pub_s: [u8; SECRET_KEY_SIZE],
    pub priv_u: [u8; SECRET_KEY_SIZE],
}

impl Envelope {
    pub fn new(
        pub_u: &[u8],
        priv_u: &[u8],
        pub_s: &[u8],
    ) -> Result<Self, ()> {
        if pub_u.len() != 32 {
            return Err(());
        }
        if priv_u.len() != 32 {
            return Err(());
        }
        if pub_s.len() != 32 {
            return Err(());
        }
        let mut pub_u_env: [u8; PUBLIC_KEY_SIZE] = [0u8; PUBLIC_KEY_SIZE];
        let mut priv_u_env: [u8; SECRET_KEY_SIZE] = [0u8; SECRET_KEY_SIZE];
        let mut pub_s_env: [u8; SECRET_KEY_SIZE] = [0u8; SECRET_KEY_SIZE];
        pub_u_env.copy_from_slice(&pub_u[..PUBLIC_KEY_SIZE]);
        priv_u_env.copy_from_slice(&priv_u[..SECRET_KEY_SIZE]);
        pub_s_env.copy_from_slice(&pub_s[..SECRET_KEY_SIZE]);

        Ok(Envelope {
            pub_u: pub_u_env,
            priv_u: priv_u_env,
            pub_s: pub_s_env,
        })
    }

    pub fn encrypt(&self, rwd_u: &[u8]) -> Vec<u8> {
        // HKDF: HMAC-based Extract-and-Expand:https://tools.ietf.org/html/rfc5869
        // see section on to "salt or not to salt", currently not salting
        let hkdf = Hkdf::<Sha512>::new(None, &rwd_u);
        let mut output_key_material = [0u8; 44]; // 32 byte key + 96 bit nonce
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap(); // domain separation
        hkdf.expand(&info, &mut output_key_material).unwrap();

        let encryption_key: GenericArray<u8, typenum::U32> =
            GenericArray::clone_from_slice(&output_key_material[0..32]);
        let aead = Aes256GcmSiv::new(encryption_key);
        let nonce: GenericArray<u8, typenum::U12> =
            GenericArray::clone_from_slice(&output_key_material[32..44]);

        let payload: Vec<u8> = bincode::serialize(&self).unwrap();
        return aead.encrypt(&nonce, payload.as_slice()).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Keypair};
    use rand_os::OsRng;
    use sha3::{Digest, Sha3_512};

    use super::*;

    #[test]
    fn build_envelope() {
        let key_too_small: [u8; 31] = [0u8; 31];
        let envelope = Envelope::new(&key_too_small, &key_too_small, &key_too_small);
        assert_eq!(envelope.is_err(), true);

        let key_too_big: [u8; 33] = [0u8; 33];
        let envelope = Envelope::new(&key_too_big, &key_too_big, &key_too_big);
        assert_eq!(envelope.is_err(), true);
    }

    #[test]
    fn ciphering() {
        let mut cspring = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut cspring);

        let priv_u = keypair.secret.to_bytes();
        let pub_u = keypair.public.to_bytes();

        let keypair: Keypair = Keypair::generate(&mut cspring);
        let pub_s = keypair.public.to_bytes();

        let envelope = Envelope::new(&pub_u, &priv_u, &pub_s).unwrap();

        let password = "gopro";
        let mut hasher = Sha3_512::new();
        hasher.input(password.as_bytes());

        let rwd_u = hasher.result();

        envelope.encrypt(&rwd_u);
    }
}
