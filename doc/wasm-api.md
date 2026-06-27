# WASM API Reference

:::warning DISCLAIMER
This codebase is AI-generated and has not undergone security audits.
:::

The WebAssembly bindings are compiled using `wasm-pack`.

## Classes

### `Identity`
- `new Identity()`: Generates a new identity.
- `export_public() -> Uint8Array`: Export public key.
- `export_public_b64() -> string`: Export public key base64.
- `export_secret() -> Uint8Array`: Export secret key.
- `Identity.from_secret_bytes(data: Uint8Array) -> Identity`: Load identity.

### `PublicKey`
- `new PublicKey(data: Uint8Array)`: Load public key.
- `PublicKey.from_b64(s: string) -> PublicKey`: Load from base64.

---

## Global Functions

- `encrypt(data: Uint8Array, recipient: PublicKey) -> Uint8Array`: Encrypt envelope.
- `encrypt_signed(data: Uint8Array, recipient: PublicKey, sender: Identity) -> Uint8Array`: Encrypt and sign.
- `decrypt(envelope: Uint8Array, recipient: Identity) -> Uint8Array`: Decrypt.
- `decrypt_verified(envelope: Uint8Array, recipient: Identity, sender: PublicKey) -> Uint8Array`: Decrypt and verify.
