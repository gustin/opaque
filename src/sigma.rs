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
    fn new() {}
}




#[cfg(test)]
mod tests {
    use super::*;

    #[test]




}

