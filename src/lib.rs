
//use rand::rngs::OsRng;
//use ed25519_dalek::Keypair;
//use ed25519_dalek::PublicKey;


struct RegistrationResult {
}

pub fn registration(user_id: u8, alpha: u8) -> u8 {
    // S chooses OPRF key kU (random and independent for each user U) and
    // sets vU = g^kU;


    // it also chooses its own pair of private-public
    // keys PrivS and PubS for use with protocol KE (the server can use
    // the same pair of keys with multiple users), and sends PubS to U.
    // CSPRING: just using OS's PRNG for now
//    let mut csprng: OsRng = OsRng::new().unwrap();
    // Generate a keypair
//    let keypair: Keypair = Keypair::generate(&mut csprng);
//    let _public_key: PublicKey = keypair.public;


    // S stores (EnvU, PubS, PrivS, PubU, kU, vU) in a user-specific
    // record.  If PrivS and PubS are used for multiple users, S can
    // store these values separately and omit them from the user's
    // record.



    // Note (salt).  We note that in OPAQUE the OPRF key acts as the secret
    // salt value that ensures the infeasibility of pre-computation attacks.
    // No extra salt value is needed.




    // Note (password rules).  The above procedure has the significant
    // advantage that the user's password is not disclosed to the server
    // even during registration.  Some sites require learning the user's
    // password for enforcing password rules.  Doing so voids this important
    // security property of OPAQUE and is not recommended.  Moving the
    // password check procedure to the client side is a more secure
    // alternative.

    8
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
