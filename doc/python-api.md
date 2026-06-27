# Python API Reference

:::warning DISCLAIMER
This codebase is AI-generated and has not undergone security audits.
:::

The Python bindings are exposed in the `quantumvault` package.

## Classes

### `Identity`
Represents a hybrid private key identity:
- `Identity(label=None)`: Constructor to generate a new key pair.
- `public_key`: Property returning the associated `PublicKey` instance.
- `export_public() -> bytes`: Export public key as bytes.
- `export_public_b64() -> str`: Export public key as base64.
- `export_secret() -> bytes`: Export private key as bytes.
- `from_secret_bytes(data: bytes) -> Identity`: Classmethod to import from bytes.

### `PublicKey`
Represents a hybrid public key:
- `PublicKey(data: bytes)`: Constructor to load public key from bytes.
- `from_b64(s: str) -> PublicKey`: Classmethod to load from base64.

---

## Module Functions

- `encrypt(data: bytes, recipient: PublicKey, sender: Identity = None) -> bytes`: Encrypt payload.
- `decrypt(envelope: bytes, recipient: Identity, sender_public: PublicKey = None) -> bytes`: Decrypt envelope.
- `sign(data: bytes, identity: Identity) -> bytes`: Detached ML-DSA signing.
- `verify(data: bytes, signature: bytes, public_key: PublicKey)`: Detached verification. Raises `ValueError` if invalid.
