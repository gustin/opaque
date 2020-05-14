
use key_exchange;


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Envelope {
    pub priv_u: [u8; KEY_SIZE],
    pub pub_u: [u8; KEY_SIZE],
    pub pub_s: [u8; KEY_SIZE],
}

impl Envelope {
    fn new(pub_u: &[u8; KEY_SIZE], priv_u: &[u8; KEY_SIZE], pub_s: &[u8; KEY_SIZE]) {
    }


    fn cipher(&self, &rwd_u: kk) {
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
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_envelope() {


    }


    #[test]
    fn ciphering() {
        let mut cspring = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut cspring);

        let priv_u = keypair.secret.to_bytes();
        let pub_u = keypair.public.to_bytes();

        let keypair: Keypair = Keypair::generate(&mut cspring);
        let pub_s = keypair.public.to_bytes();

        envelope = Envelope.new {
            pub_u,
            priv_u,
            pub_s,
        };

        let password = "gopro";
        let mut hasher = Sha3_512::new();
        hasher.input(password.as_bytes());

        let rwd_u = hasher.result();

        envelope.cipher(&rwd_u);
    }
}
