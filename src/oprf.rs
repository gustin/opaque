

pub trait Oprf {}
pub trait VerifiedOprf {}

//  Protocol for computing DH-OPRF, U with input x and S with input k:
//  U: choose random r in [0..q-1], send alpha=H'(x)*g^r to S

// The simplified form with the base point factor dropped:
// spec: alpha=(H'(x))^r in the first message and set the
//      function output to H(x,v,beta^{1/r})
