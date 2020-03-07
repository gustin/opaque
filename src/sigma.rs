use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyExchange {
    pub identity: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub mac: [u8; 32],
    // nonce, sid, info
}

impl KeyExchange {
    ///##
    /// Construct a KeyExchange from the bytes of a previously formed
    /// KeyExchange.
    ///
    /// # Inputs
    ///
    /// * `bytes`: an `&[u8]` representing a KeyExchange.
    ///
    /// # Warning
    ///
    /// If you give this function bytes which do not represent a KeyExchange
    /// it will be broken.
    //
    /// # Returns
    ///
    /// A `Result` whose okay value is an `KeyExchange` or whose error value
    /// is an `KeyExchangeError` describing the error that occurred.
    pub fn from_bytes<'a>(bytes: &'a [u8]) -> Result<KeyExchange, Error> {
        Ok(KeyExchange {
            identity: [0u8; 32],
            signature: [0u8; 32],
            mac: [0u8; 32],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_1() {
        key_bytes = [u8; 32];
        key_exchange = KeyExchange::from_bytes(key_bytes);
    }
}
