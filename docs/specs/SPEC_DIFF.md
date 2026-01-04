# OPAQUE Specification Diff: draft-03 → RFC 9807

Migration notes from draft-krawczyk-cfrg-opaque-03 (Oct 2019) to RFC 9807 (July 2025).

---

## TL;DR

They changed *everything*. The envelope no longer encrypts your keys - it derives
them deterministically. SIGMA-I is out, 3DH is in. Password stretching went from
"maybe do this" to "you must do this." And there's a whole new anti-enumeration
dance with XOR masking.

Basically: same vibes, completely different protocol.

| Aspect | draft-03 | RFC 9807 |
|--------|----------|----------|
| Components | OPRF + KE | OPRF + Key Recovery + AKE |
| KE Protocol | HMQV / SIGMA-I | 3DH (primary) |
| Envelope | Encrypted credentials | Auth-only, derived keys |
| OPRF | Custom DH-OPRF | RFC 9497 prime-order OPRF |
| Blinding | Multiplicative (g^r) | Standard per RFC 9497 |
| Password stretch | Optional | Required (Argon2id/scrypt) |
| Client enumeration | Informal | masking_key + XOR |
| Test vectors | None | Comprehensive |

---

## 1. Architecture Changes

### draft-03: Two Components
```
OPAQUE = OPRF + KE
```
- Protocol is composition of OPRF and key exchange
- KE protocols: HMQV, SIGMA-I, or TLS 1.3 integration

### RFC 9807: Three Components
```
OPAQUE = OPRF + Key Recovery + AKE
```
- Explicit separation of credential recovery from key exchange
- OPRF per RFC 9497 (not custom)
- AKE instantiated as 3DH (SIGMA-I/HMQV relegated to appendix)

**Migration:** Refactor to separate key recovery logic from AKE.

---

## 2. OPRF Protocol

### draft-03: Custom DH-OPRF
```
F(k; x) = H(x, v, H'(x)^k)   where v = g^k

Blinding: alpha = H'(x) * g^r  (multiplicative)
Response: beta = alpha^k, v = g^k
Output:   H(x, v, beta * v^{-r})
```
- Includes `v = g^k` in the hash output
- Multiplicative blinding with fixed-base optimization

### RFC 9807: RFC 9497 OPRF (modeOPRF = 0x00)
```
Blind(password) → (blind, blinded_element)
BlindEvaluate(oprf_key, blinded_element) → evaluated_element
Finalize(password, blind, evaluated_element) → oprf_output
```
- Standard prime-order OPRF construction
- No `v` value transmitted or hashed
- References RFC 9497 for all OPRF operations

**Migration:**
- Replace custom OPRF with RFC 9497 implementation
- Remove `v = g^k` from protocol flow
- Use standard Blind/BlindEvaluate/Finalize API

---

## 3. OPRF Key Derivation

### draft-03
```
kU = random()  // per-user random key
vU = g^kU      // stored and transmitted
```

### RFC 9807
```
seed = Expand(oprf_seed, concat(credential_identifier, "OprfKey"), Nok)
(oprf_key, _) = DeriveKeyPair(seed, "OPAQUE-DeriveKeyPair")
```
- Deterministic from server's `oprf_seed` and client's `credential_identifier`
- Single `oprf_seed` recommended for all clients (enumeration defense)

**Migration:**
- Add server-side `oprf_seed` parameter
- Replace random key generation with deterministic derivation
- Store `credential_identifier` per client

---

## 4. Envelope Construction

### draft-03: Encrypted Envelope
```rust
EnvU = AuthEnc(RwdU; PrivU, PubU, PubS)
```
- Full authenticated encryption of private key and public keys
- RwdU derived directly from OPRF output
- Random-key robustness required for AuthEnc

### RFC 9807: Authentication-Only Envelope
```rust
struct Envelope {
    envelope_nonce: [u8; Nn],  // 32 bytes
    auth_tag: [u8; Nm],        // MAC tag
}
```
- Private key **derived** from `randomized_password` + `envelope_nonce`
- Only stores nonce + authentication tag
- Keys derived via HKDF:
  ```
  masking_key = Expand(randomized_password, "MaskingKey", Nh)
  auth_key = Expand(randomized_password, concat(nonce, "AuthKey"), Nh)
  export_key = Expand(randomized_password, concat(nonce, "ExportKey"), Nh)
  seed = Expand(randomized_password, concat(nonce, "PrivateKey"), Nseed)
  (client_private_key, client_public_key) = DeriveDiffieHellmanKeyPair(seed)
  ```

**Migration:**
- Remove envelope encryption (AES-GCM-SIV no longer needed for envelope)
- Implement deterministic key derivation from password
- Add masking_key, auth_key, export_key derivation
- Store smaller envelope structure

---

## 5. Password Processing

### draft-03
```
RwdU = DH-OPRF(password)
// Optional: RwdU = KDF(RwdU) for hardening
```

### RFC 9807
```
oprf_output = Finalize(password, blind, evaluated_element)
stretched_oprf_output = Stretch(oprf_output)  // REQUIRED
randomized_password = Extract("", concat(oprf_output, stretched_oprf_output))
```
- Password stretching is **mandatory**
- Recommended: Argon2id with specific parameters:
  ```
  Argon2id(S=zeroes(16), p=4, T=Nh, m=2^21, t=1, v=0x13, K=nil, X=nil, y=2)
  ```
- Alternative: scrypt(N=2^15, r=8, p=1)

**Migration:**
- Implement required Stretch() function
- Add Argon2id dependency
- Update key derivation to use randomized_password

---

## 6. Key Exchange Protocol

### draft-03: HMQV or SIGMA-I
```
SIGMA-I:
  KE1 = g^x
  KE2 = g^y, Sig(PrivS; g^x, g^y), Mac(Km1; IdS)
  KE3 = Sig(PrivU; g^y, g^x), Mac(Km2; IdU)
```
- Signature-based authentication
- Key derivation from g^xy

### RFC 9807: 3DH (Triple Diffie-Hellman)
```
Client sends: client_nonce, client_public_keyshare (g^x)
Server sends: server_nonce, server_public_keyshare (g^y), server_mac
Client sends: client_mac

DH computations:
  dh1 = DH(client_secret, server_public_keyshare)      // g^xy
  dh2 = DH(client_secret, server_public_key)           // g^x * server_static
  dh3 = DH(client_private_key, server_public_keyshare) // client_static * g^y
  ikm = concat(dh1, dh2, dh3)
```
- MAC-based authentication (no signatures in core protocol)
- Three DH operations for key material
- TLS 1.3-style key schedule

**Migration:**
- Replace SIGMA with 3DH
- Remove signature operations from core protocol
- Implement 3-way DH key derivation
- Add TLS 1.3-style Expand-Label/Derive-Secret

---

## 7. Key Schedule

### draft-03
- Informal, implementation-defined
- Keys derived from single DH value

### RFC 9807: TLS 1.3-style
```
Expand-Label(Secret, Label, Context, Length) =
    Expand(Secret, CustomLabel, Length)

struct CustomLabel {
    uint16 length;
    opaque label<8..255> = "OPAQUE-" + Label;
    uint8 context<0..255>;
}

Derive-Secret(Secret, Label, Transcript-Hash) =
    Expand-Label(Secret, Label, Transcript-Hash, Nx)
```

Key derivation:
```
prk = Extract("", ikm)
handshake_secret = Derive-Secret(prk, "HandshakeSecret", Hash(preamble))
session_key = Derive-Secret(prk, "SessionKey", Hash(preamble))
Km2 = Derive-Secret(handshake_secret, "ServerMAC", "")
Km3 = Derive-Secret(handshake_secret, "ClientMAC", "")
```

**Migration:**
- Implement Expand-Label and Derive-Secret
- Use structured key schedule
- Include full transcript in preamble

---

## 8. Message Structures

### draft-03
- Informal message descriptions
- No wire format specification

### RFC 9807: Formal Structures

**Registration:**
```
struct RegistrationRequest {
    uint8 blinded_message[Noe];
}

struct RegistrationResponse {
    uint8 evaluated_message[Noe];
    uint8 server_public_key[Npk];
}

struct RegistrationRecord {
    uint8 client_public_key[Npk];
    uint8 masking_key[Nh];
    Envelope envelope;
}
```

**Authentication:**
```
struct CredentialRequest {
    uint8 blinded_message[Noe];
}

struct CredentialResponse {
    uint8 evaluated_message[Noe];
    uint8 masking_nonce[Nn];
    uint8 masked_response[Npk + Nn + Nm];  // XOR-encrypted
}

struct KE1 {
    CredentialRequest credential_request;
    AuthRequest auth_request;
}

struct KE2 {
    CredentialResponse credential_response;
    AuthResponse auth_response;
}

struct KE3 {
    uint8 client_mac[Nm];
}
```

**Migration:**
- Define formal message structs
- Implement serialization per TLS 1.3 syntax (RFC 8446 Section 3)

---

## 9. Client Enumeration Defense

### draft-03
- Informal suggestion: fake responses for unknown users
- Server generates fake kU, EnvU for non-existent users

### RFC 9807: masking_key Mechanism
```
// Server stores per-client:
masking_key = Expand(randomized_password, "MaskingKey", Nh)

// Response construction:
masking_nonce = random(Nn)
credential_response_pad = Expand(masking_key,
                                 concat(masking_nonce, "CredentialResponsePad"),
                                 Npk + Nn + Nm)
masked_response = xor(credential_response_pad,
                      concat(server_public_key, envelope))
```
- XOR-based masking of response
- Fake records indistinguishable without correct password
- Recommended: pre-generate one fake record for all unknown users

**Migration:**
- Add masking_key to registration record
- Implement XOR masking for credential responses
- Create fake record handling

---

## 10. Cryptographic Primitives

### draft-03
- Generic "cyclic group G of prime order q"
- H' for hash-to-curve
- HMAC for MACs
- HKDF for key derivation

### RFC 9807: Specific Configurations

**Recommended configuration (ristretto255-SHA512):**
| Primitive | Specification |
|-----------|---------------|
| OPRF | ristretto255-SHA512 (RFC 9497) |
| KDF | HKDF-SHA-512 (RFC 5869) |
| MAC | HMAC-SHA-512 (RFC 2104) |
| Hash | SHA-512 |
| KSF | Argon2id |
| Group | ristretto255 (RFC 9496) |

**Sizes:**
| Parameter | ristretto255-SHA512 |
|-----------|---------------------|
| Noe | 32 |
| Nok | 32 |
| Npk | 32 |
| Nsk | 32 |
| Nn | 32 |
| Nm | 64 |
| Nh | 64 |
| Nx | 64 |

**Migration:**
- Update to ristretto255 (currently using curve25519-dalek Ristretto)
- Switch from SHA-256/SHA3 to SHA-512
- Add Argon2id dependency
- Update HMAC to 512-bit

---

## 11. Identity Handling

### draft-03
- IdU, IdS mentioned informally
- Included in signature/MAC computations

### RFC 9807: CleartextCredentials
```
struct CleartextCredentials {
    uint8 server_public_key[Npk];
    uint8 server_identity<1..2^16-1>;
    uint8 client_identity<1..2^16-1>;
}
```
- Identities default to public keys if not specified
- Bound into auth_tag during envelope creation
- Included in preamble for key derivation

**Migration:**
- Implement CleartextCredentials structure
- Add identity binding to envelope auth_tag
- Include identities in transcript preamble

---

## 12. Test Vectors

### draft-03
None provided.

### RFC 9807
Comprehensive test vectors in Appendix C:
- 6 "real" test vectors (ristretto255, P-256)
- 3 "fake" test vectors (enumeration defense)
- All intermediate values provided

**Migration:**
- Implement test vector validation
- Use vectors to verify correctness during migration

---

## Migration Checklist

### Phase 1: Core Primitives
- [ ] Replace custom OPRF with RFC 9497 implementation
- [ ] Add Argon2id key stretching
- [ ] Update to ristretto255 group operations
- [ ] Implement RFC 9497 Blind/BlindEvaluate/Finalize

### Phase 2: Envelope Redesign
- [ ] Remove AES-GCM-SIV envelope encryption
- [ ] Implement deterministic key derivation from seed
- [ ] Add masking_key derivation and storage
- [ ] Implement new Envelope structure (nonce + auth_tag)

### Phase 3: Key Exchange
- [ ] Replace SIGMA-I with 3DH
- [ ] Implement triple-DH key computation
- [ ] Add TLS 1.3-style key schedule
- [ ] Implement Expand-Label and Derive-Secret

### Phase 4: Message Structures
- [ ] Define formal message types
- [ ] Implement serialization/deserialization
- [ ] Add CleartextCredentials handling

### Phase 5: Client Enumeration
- [ ] Implement XOR-masked credential responses
- [ ] Add fake record generation
- [ ] Ensure constant-time operations

### Phase 6: Validation
- [ ] Pass all RFC 9807 test vectors
- [ ] Security review of implementation
- [ ] Zeroization of sensitive values

---

## Dependencies Update

### Current (draft-03)
```toml
curve25519-dalek = "1.2.3"
ed25519-dalek = "1.0.0-pre.2"
aes-gcm-siv = "0.2.1"  # BROKEN - yanked deps
sha2 = "0.8.0"
sha3 = "0.8.2"
hkdf = "0.8.0"
hmac = "0.7.1"
```

### Required (RFC 9807)
```toml
# OPRF (RFC 9497)
voprf = "0.5"  # or implement per spec

# Ristretto255
curve25519-dalek = "4.x"

# Key stretching
argon2 = "0.5"

# Hashing
sha2 = "0.10"  # SHA-512

# KDF/MAC
hkdf = "0.12"
hmac = "0.12"

# Serialization
# Keep existing bincode/serde
```

---

## References

- [draft-krawczyk-cfrg-opaque-03](https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-03)
- [RFC 9807 - OPAQUE](https://www.rfc-editor.org/rfc/rfc9807)
- [RFC 9497 - OPRF](https://www.rfc-editor.org/rfc/rfc9497)
- [RFC 9496 - ristretto255](https://www.rfc-editor.org/rfc/rfc9496)
- [RFC 9106 - Argon2](https://www.rfc-editor.org/rfc/rfc9106)
