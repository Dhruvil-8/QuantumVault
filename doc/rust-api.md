# Rust API Reference

:::warning DISCLAIMER
This codebase is AI-generated and has not undergone security audits.
:::

The Rust core API is exposed in the `quantumvault-core` crate.

## Key Types

### `PQIdentity`
Represents a hybrid identity, encapsulating static secret parameters:
- `x25519_secret`
- `mlkem_secret`
- `mldsa_secret`

**Key Methods**:
- `generate() -> QVResult<Self>`: Generate a new random identity.
- `from_secret_bytes(data: &[u8]) -> QVResult<Self>`: Reconstruct from exported secret key bytes.
- `export_public() -> QVResult<Vec<u8>>`: Export public key bytes.
- `export_secret() -> QVResult<Vec<u8>>`: Export secret key bytes.

### `PQPublicKey`
Represents the public keys of an identity:
- `x25519_public`
- `mlkem_public`
- `mldsa_public`

**Key Methods**:
- `from_bytes(data: &[u8]) -> QVResult<Self>`: Load public key from bytes.

---

## File Encryption and Decryption

### `PQFile`
Handles container envelope operations:
- `encrypt(plaintext: &[u8], recipient: &PQPublicKey) -> QVResult<Vec<u8>>`: Encrypt envelope for recipient (anonymous).
- `encrypt_and_sign(plaintext: &[u8], recipient: &PQPublicKey, sender: &PQIdentity) -> QVResult<Vec<u8>>`: Encrypt envelope and sign with sender identity.
- `decrypt_and_verify(envelope: &[u8], recipient: &PQIdentity, sender_public: Option<&PQPublicKey>) -> QVResult<Vec<u8>>`: Decrypt envelope and verify sender signature.
