

## Domain Model

Goal:  To abstract out the current procedural style of code, so it's less
like Pascal from back in the 90's.

![turbo](https://upload.wikimedia.org/wikipedia/commons/d/df/Turbo_Pascal_7.0_Scrren.png)

### Modules

## OPRF

### Client

  - Registration Start: Calculates Alpha, KeyPair (pub/private), R
  - Registration Finalize: Calculates Envelope Ciphered

Shared between calls: password, pub_u, pub_s, priv_u, R

  - Authenticate Start: Calculates Alpha, R
  - Authenticate Final: Calculates

Shared between calls: password, keypair, R

### Server

  - Registration Start: Calculates beta, v, pub_s
  - Registration Finalize: Stores result

  - Authentication Start:
  - Authentication Finalize:

Shared between calls:

## OPAQUE

  ### Structs


## Key Exchange

  Trait:
    * ke_1 - generate the first key for key exchange.
      * No inputs
      * Returns ke_1 as u8; 32
    * ke_2 - derive the second key in the exchange.
      * Input: ke_1
      * Returns ke_2 as u8; 32
    * ke_3 - derive the third key in the exchange.
      * Input: ke_2
      * Returns ke_3 as u8; 32

* Sigma: private functions specific to Sigma Key Exchange Implementation to fulfil
the above triats
    * SIGa(g^y, g^x)
    * MAC(Km; PubS)





