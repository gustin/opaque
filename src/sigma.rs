use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyExchange<'a> {
    pub identity: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub signature: &'a [u8],
    #[serde(with = "serde_bytes")]
    pub mac: Vec<u8>,
    // nonce, sid, info
}

impl KeyExchange<'_> {
    ///##
    /// Construct a KeyExchange from the bytes of a previously formed
    /// KeyExchange.
    ///
    /// # Inputs
    ///
    /// * `bytes`: an `&[u8]` representing a KeyExchange.
    ///
    /// # Returns
    ///
    /// A KeyExchange formed from bytes.
    ///
    /// # Warning
    ///
    /// If you give this function bytes which do not represent a KeyExchange
    /// it will be broken.
    ///
    pub fn from_bytes<'a>(_bytes: &'a [u8]) -> KeyExchange {
        KeyExchange {
            identity: [0u8; 32],
            signature: &[0u8; 64],
            mac: vec![1, 2, 3, 4],
        }
    }
}

// let ke_1 = RISTRETTO_BASEPOINT_POINT * x;
// let ke_2: RistrettoPoint = RISTRETTO_BASEPOINT_POINT * user_record.k_u;

//
//

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_1() {
        let key_bytes: [u8; 32] = [
            72, 79, 202, 45, 141, 212, 156, 96, 121, 69, 228, 3, 178, 12, 144,
            236, 246, 53, 133, 85, 149, 25, 244, 215, 69, 178, 20, 242, 112,
            154, 116, 41,
        ];
        let _key_exchange = KeyExchange::from_bytes(&key_bytes);
    }
}
