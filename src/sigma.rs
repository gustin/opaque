use serde::{Deserialize, Serialize};
use std::error::Error;

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
    pub fn from_bytes<'a>(bytes: &'a [u8]) -> KeyExchange {
        KeyExchange {
            identity: [0u8; 32],
            signature: &[0u8; 64],
            mac: vec![1,2,3,4],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_1() {
        let key_bytes = [0u8; 32];
        let key_exchange = KeyExchange::from_bytes(&key_bytes);
    }
}
