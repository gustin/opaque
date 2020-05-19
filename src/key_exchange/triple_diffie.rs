use crate::key_exchange::KeyExchange;
use crate::key_exchange::KeyExchangeComm;


pub struct TripleDiffie();

impl KeyExchangeProtocol for TripleDiffie {
    fn initiate_handshake(&self) {
        // SIGMA-I
        // sidA, g^x, nA, infoA
        // sidA: session identifier chosen by each party for the ongoing session, is returned by B
        // g^x: basepoint times random scalar x
        // nA: nonce, fresh and anew with each session
        // info: any additional info to be carried in the protocol, not required (could be protocol
        // name, version, message number, etc)
        // -> client sends scalar * base point
    }
    fn responder_handshake(&self) {
        //  SIGMA
        //  KE2 = g^y, Sig(PrivS; g^x, g^y), Mac(Km1; IdS)

        // sidA:
        // sidB
        // g^y
        // nB
        // infoB
        // server sends, g^y, SIgn(privS; g^x, g^y), Mac(Km1; IdS)
    }
    fn initiator_response(&self) {
        // SIGMA

        //  KE3 = Sig(PrivU; g^y, g^x), Mac(Km2; IdU)
        // { A, SIGa(g^y, g^x), MAC(Km; A) } Ke

        // client sends -> Sig(PrivU; g^y, g^x), Mac(Km2; IdU)
    }
    fn responder_response(&self) {
        // server verifies request
    }
}


