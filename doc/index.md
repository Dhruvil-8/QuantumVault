# QuantumVault PQC SDK

:::warning DISCLAIMER
This codebase is AI-generated. No professional security or cryptographic audits have been performed. Use it at your own risk.
:::

QuantumVault is a developer-focused Post-Quantum Cryptography (PQC) SDK. It provides simple, high-level APIs for key encapsulation, digital signatures, and file locking, wrapping advanced hybrid algorithms in safe abstractions.

## Encrypt a File in 3 Lines of Python

```python
from quantumvault import Identity, encrypt, decrypt

alice = Identity()
bob = Identity()

# Encrypt for Bob, signing as Alice
envelope = encrypt(b"Hello post-quantum world!", bob.public_key, sender=alice)

# Decrypt using Bob's identity and Alice's public key
plaintext = decrypt(envelope, bob, sender_public=alice.public_key)
# b"Hello post-quantum world!"
```

## Key Capabilities
- **Hybrid Key Encapsulation**: Connects classical X25519 ECDH with FIPS-203 ML-KEM-1024.
- **Detached Authenticity Signatures**: ML-DSA-87 (FIPS-204) signatures on all files.
- **Symmetric Wiping**: Verified zeroization on drop for key variables and structures.
- **Cross-Platform Portability**: 100% pure Rust cryptographic engines with zero native C compiler dependencies.
- **Language Bindings**: Native interfaces for Rust, Python, WebAssembly (JavaScript), and C/C++.
