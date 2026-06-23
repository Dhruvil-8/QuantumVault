# QuantumVault

QuantumVault is a post-quantum secure file encryption locker and key manager. It implements the latest NIST standards alongside classical primitives in a **hybrid cryptographic model** to guarantee security against both quantum and classical adversaries.

This repository features:
1. **`quantumvault-core`:** A pure Rust library implementing the cryptographic core.
2. **`quantumvault-cli`:** A lightweight, dependency-free command-line interface.
3. **`quantumvault-gui`:** A high-performance, native GPU-rendered desktop application built using `eframe` and `egui` (replacing the old Tauri/HTML stack with a 100% Rust solution).

---

## Cryptographic Architecture (Max Paranoia - Version 6)

QuantumVault uses a **hybrid key encapsulation** approach:
* **Classical Layer:** X25519 ECDH (RFC 7748) provides audited classical security, hardened with the `zeroize` feature.
* **Post-Quantum Layer:** ML-KEM-1024 (FIPS 203) provides maximum-strength quantum-resistant key exchange (NIST Category 5).
* **Signatures (Authenticity):** ML-DSA-87 (FIPS 204) signs the vault header, ensuring that files cannot be tampered with or replaced (NIST Category 5).
* **Symmetric Encryption:** File content is encrypted in 8 MiB chunks using **ChaCha20-Poly1305** authenticated encryption.
* **Key Derivation (KDF):** Secrets are combined using **HKDF-SHA3-512** with 64-byte outputs.
* **Hardened Metadata**: Uses **64-byte** (512-bit) random salts and nonce seeds to maximize cryptographic entropy.

```text
┌─────────────────────────────────────────────────────────────┐
│                 QuantumVault File (.qvault)                 │
├─────────────────────────────────────────────────────────────┤
│  Header                                                     │
│  ├─ Magic: "QVLT"                                           │
│  ├─ Version: 6                                              │
│  ├─ Ephemeral X25519 Public Key (32 bytes)                 │
│  ├─ ML-KEM Ciphertext (1568 bytes)                          │
│  ├─ ML-DSA Signature (4627 bytes)                           │
│  ├─ Salt (64 bytes)                                         │
│  └─ Nonce Seed (64 bytes)                                   │
├─────────────────────────────────────────────────────────────┤
│  Encrypted Payload (ChaCha20-Poly1305, chunked)             │
└─────────────────────────────────────────────────────────────┘
```

---

## Workspace Structure

The project is structured as a Cargo workspace:
* `/quantumvault-core`: The cryptographic core library containing KEM, DSA, KDF, and file chunk streams.
* `/quantumvault-cli`: The CLI utility for keygen, encryption, and decryption.
* `/quantumvault-gui`: The native GPU-rendered desktop application.

---

## Getting Started

### Prerequisites

* Rust (latest stable toolchain, aligned on **Rust Edition 2024**).

---

### Running the CLI Client

You can build and run the CLI directly:

#### 1. Generate cryptographic keys (Identity)
Generates keypairs for X25519, ML-KEM-1024, and ML-DSA-87:
```bash
cargo run -p quantumvault-cli -- keygen ./keys/alice
cargo run -p quantumvault-cli -- keygen ./keys/bob
```

#### 2. Encrypt a file
Encrypt a file for a recipient (Bob) using your identity (Alice). If the output path lacks the `.qvault` extension, it will be automatically appended:
```bash
cargo run -p quantumvault-cli -- encrypt -i document.pdf -o document.pdf.qvault -s ./keys/alice -r ./keys/bob/encryption
```

#### 3. Decrypt a file
Decrypt a file using your identity (Bob) and verifying the sender's public key (Alice):
```bash
cargo run -p quantumvault-cli -- decrypt -i document.pdf.qvault -o document_decrypted.pdf -r ./keys/bob -s ./keys/alice/signing
```

---

### Running the Desktop GUI Client

You can run the GUI directly:
```bash
cargo run -p quantumvault-gui --release
```

---

## Cryptographic Disclaimer

> [!WARNING]
> This software is experimental and is an AI-generated codebase. It implements the finalized NIST FIPS 203 (ML-KEM-1024) and FIPS 204 (ML-DSA-87) standards, but the code has **not** undergone a professional third-party cryptographic or security audit.
> Do not use this software for high-risk data storage or production environments securing critical assets. Use it at your own risk.

---

## License

This project is licensed under the MIT License.
