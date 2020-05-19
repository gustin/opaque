use crate::key_exchange::KeyExchangeComm;
use crate::oprf::*;
use crate::key_exchange::sigma::*;
use crate::key_exchange::triple_diffie::*;

// Opaque can take an OPRF type and a Key Exchange

pub struct Opaque<T: KeyExchangeComm, U: Oprf> {
    key_exchange: T,
    oprf: U,
}


impl<T: KeyExchangeComm, U: Oprf> Opaque<T, U> {
    pub fn registration(&self) {
        self.key_exchange.initiate_handshake();
    }
}

// Type T where T is a Key Exchange and an OPRF

pub type OpaqueSigma = Opaque<SigmaI, Oprf>;
pub type Opaque3Dh = Opaque<TripleDiffie, VerifiedOprf>;
