
use serde::{Deserialize, Serialize};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyExchange<'a> {
    pub identity: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub signature: &'a [u8],
    #[serde(with = "serde_bytes")]
    pub mac: Vec<u8>,
    // nonce, sid, info
}


impl KeyExchange {

    fn new() {


    }

}
