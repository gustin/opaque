use crate::key_exchange::KeyExchangeProtocol;
use crate::oprf::*;
use crate::key_exchange::sigma::*;
use crate::key_exchange::triple_diffie::*;

// Opaque can take an OPRF type and a Key Exchange

pub struct Opaque<T: KeyExchangeProtocol, U: Oprf> {
    key_exchange: T,
    oprf: U,
}


impl<T: KeyExchangeProtocol, U: Oprf> Opaque<T, U> {
    pub fn registration(&self) {
        self.key_exchange.initiate_handshake();
    }
}

// Type T where T is a Key Exchange and an OPRF

pub type OpaqueSigma = Opaque<SigmaI, Oprf>;
pub type Opaque3Dh = Opaque<TripleDiffie, VerifiedOprf>;
