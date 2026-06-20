# QuantumVault

QuantumVault is a post-quantum secure file encryption locker and key manager. It implements the latest NIST standards alongside classical primitives in a **hybrid cryptographic model** to guarantee security against both quantum and classical adversaries.

This repository features:
1. **`quantumvault-core`:** A pure Rust library implementing the cryptographic core.
2. **`quantumvault-cli`:** A lightweight, dependency-free command-line interface.
3. **Desktop GUI App:** An elegant Tauri-based desktop app utilizing a zero-dependency, ultra-lightweight Vanilla HTML/CSS/JS frontend (no `node_modules` required!).

---

## Cryptographic Architecture

QuantumVault uses a **hybrid key encapsulation** approach:
* **Classical Layer:** X25519 ECDH (RFC 7748) provides standard classical security.
* **Post-Quantum Layer:** ML-KEM-1024 (FIPS 203) provides quantum-resistant security.
* **Signatures (Authenticity):** ML-DSA-65 (FIPS 204) signs the vault header, ensuring that files cannot be tampered with or replaced.
* **Symmetric Encryption:** File content is encrypted in 8 MiB chunks using **ChaCha20-Poly1305** authenticated encryption.
* **Key Derivation:** Secrets are combined using **HKDF-SHA3-256**.

```text
┌─────────────────────────────────────────────────────────────┐
│                    QuantumVault File (.qvault)              │
├──────────────────────────────────────────────────────────────┤
│  Header                                                       │
│  ├─ Magic: "QVLT"                                            │
│  ├─ Version: 2                                                │
│  ├─ Ephemeral X25519 Public Key (32 bytes)                   │
│  ├─ ML-KEM Ciphertext (1568 bytes)                           │
│  ├─ ML-DSA Signature (3309 bytes)                            │
│  └─ Nonce Seed (32 bytes)                                    │
├──────────────────────────────────────────────────────────────┤
│  Encrypted Payload (ChaCha20-Poly1305, chunked)              │
└──────────────────────────────────────────────────────────────┘
```

---

## Workspace Structure

The project is structured as a Cargo workspace:
* `/quantumvault-core`: The cryptographic core library containing KEM, DSA, KDF, and file chunk streams.
* `/quantumvault-cli`: The CLI application for keygen, encryption, and decryption.
* `/src-tauri`: The Tauri backend that wraps the core library to serve the GUI.
* `/frontend`: The zero-dependency Vanilla HTML/CSS/JS frontend.

---

## Getting Started

### Prerequisites

* Rust (latest stable toolchain).
* On Windows, you can compile using either the MSVC toolchain (requires Visual Studio build tools) or the GNU toolchain (`x86_64-pc-windows-gnu`).

### Running the CLI Client

You can build and run the CLI directly:

#### 1. Generate cryptographic keys (Identity)
Generates keypairs for X25519, ML-KEM, and ML-DSA:
```bash
cargo run -p quantumvault-cli -- keygen ./keys/alice
cargo run -p quantumvault-cli -- keygen ./keys/bob
```

#### 2. Encrypt a file
Encrypt a file for a recipient (Bob) using your identity (Alice):
```bash
cargo run -p quantumvault-cli -- encrypt -i document.pdf -o document.pdf.qvault -s ./keys/alice -r ./keys/bob/encryption
```

#### 3. Decrypt a file
Decrypt a file using your identity (Bob) and verifying the sender's public key (Alice):
```bash
cargo run -p quantumvault-cli -- decrypt -i document.pdf.qvault -o document_decrypted.pdf -r ./keys/bob -s ./keys/alice/signing
```

---

## Desktop GUI Client

To run the GUI:
```bash
# If using MSVC target
cargo run --bin quantumvault --features tauri

# If using GNU target on Windows
rustup run stable-x86_64-pc-windows-gnu cargo run --bin quantumvault --features tauri
```

---

## Cryptographic Disclaimer

> [!WARNING]
> This software is experimental and is an AI-generated codebase. It implements the finalized NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) standards, but the code has **not** undergone a professional third-party cryptographic or security audit.
> Do not use this software for high-risk data storage or production environments securing critical assets. Use it at your own risk.

---

## License

This project is licensed under the MIT License.
