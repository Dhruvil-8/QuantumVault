# QuantumVault PQC SDK

> [!WARNING]
> **DISCLAIMER:** This repository is an AI-generated codebase. A professional third-party cryptographic, memory safety, or security audit has **not** been performed. While unit and integration test suites run successfully, this codebase has not undergone a formal security audit. Do not use this software in production systems or high-risk environments securing critical assets. Use it at your own risk.

QuantumVault is a hybrid post-quantum secure file encryption locker and multi-language software development kit (SDK). It integrates modern NIST standards alongside classical primitives in a **hybrid cryptographic configuration** to defend files against both contemporary eavesdropping and future quantum-computing decryption attacks (such as "Harvest Now, Decrypt Later").

---

## Workspace Structure

The project is configured as a single Cargo workspace containing:
1. **`quantumvault-core`**: The pure-Rust cryptographic core implementing ML-KEM-1024 (`fips203`), ML-DSA-87 (`fips204`), X25519, and ChaCha20-Poly1305.
2. **`quantumvault-cli`**: Lightweight command-line client matching the SDK operations.
3. **`quantumvault-gui`**: Native GPU-rendered desktop client built with `egui` and `eframe`.
4. **`quantumvault-python`**: Python bindings managed via Maturin/PyO3.
5. **`quantumvault-wasm`**: WebAssembly bindings for browser-based operations.
6. **`quantumvault-ffi`**: C-compatible FFI library with automated `quantumvault.h` header generation.

---

## Cryptographic Specification

- **Classical Layer**: X25519 Elliptic Curve Diffie-Hellman (ECDH) for audited classical strength.
- **Post-Quantum KEM**: ML-KEM-1024 (FIPS 203, NIST Category 5).
- **Post-Quantum Signatures**: ML-DSA-87 (FIPS 204, NIST Category 5) applied to pre-hashed SHA3-256 digests.
- **Key Derivation (KDF)**: HKDF-SHA3-512 combining classical and PQ secrets.
- **Symmetric Encryption**: ChaCha20-Poly1305 authenticated encryption.
- **Key Storage (`.qvk`)**: Binary serialized files containing key type tags, JSON-based user metadata, payload data, and BLAKE3 checksums.
- **Envelope Container (`.qvf`)**: Packed payload wrapping KEM ciphertext, optional signature (supported via header flags byte), and AEAD encrypted data. Allows both signed and anonymous encryption modes.

---

## Getting Started & CLI Usage

### Build and Test
Run compilation and validation checks:
```bash
# Compile check all targets
$env:PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1; cargo check --all

# Run workspace tests
$env:PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1; cargo test --all
```

### CLI Client Commands
Build the CLI binary:
```bash
cargo build --release -p quantumvault-cli
```

1. **Generate Identity** (Creates a `.qvk` secret key file):
   ```bash
   quantumvault-cli keygen alice_secret.qvk --label "Alice Key" --comment "Alice PQC Identity"
   ```

2. **Export Public Key**:
   ```bash
   quantumvault-cli export-public -s alice_secret.qvk -o alice_public.qvk
   ```

3. **Encrypt File** (Encapsulates key for recipient and signs payload):
   ```bash
   quantumvault-cli encrypt -i plaintext.txt -o ciphertext.qvf -s alice_secret.qvk -r bob_public.qvk
   ```

4. **Decrypt File** (Decrypts ciphertext and verifies sender's signature):
   ```bash
   quantumvault-cli decrypt -i ciphertext.qvf -o decrypted.txt -r bob_secret.qvk -s alice_public.qvk
   ```

---

## Multi-Language Integrations

### Python SDK (`quantumvault-python`)
Install using Maturin and run in Python:
```python
from quantumvault import Identity, PublicKey, encrypt, decrypt

# Generate identities
alice = Identity(label="Alice")
bob = Identity(label="Bob")

# Encrypt & Sign
ciphertext = encrypt(b"Confidential payload", bob.public_key, sender=alice)

# Decrypt & Verify
plaintext = decrypt(ciphertext, bob, sender_public=alice.public_key)
print(plaintext.decode())  # "Confidential payload"
```

### WebAssembly (`quantumvault-wasm`)
Import the generated WASM package in JS/TS:
```javascript
import { Identity, PublicKey, encrypt, decrypt_verified } from "./pkg/quantumvault_wasm.js";

const alice = new Identity();
const bob = new Identity();

const ciphertext = encrypt(new TextEncoder().encode("Hello WASM"), bob.public_key());
const decrypted = decrypt_verified(ciphertext, bob, alice.public_key());
```

### C FFI (`quantumvault-ffi`)
Include the generated header:
```c
#include "quantumvault.h"

// Generate Alice identity handle
struct QVIdentityHandle* alice = qv_identity_generate();

// Clean up handle
qv_identity_free(alice);
```
Header location: [quantumvault-ffi/quantumvault.h](quantumvault-ffi/quantumvault.h)
