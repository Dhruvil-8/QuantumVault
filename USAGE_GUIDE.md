# QuantumVault Operations & Usage Guide

QuantumVault is a high-performance, post-quantum secure file encryption locker and key manager. It integrates NIST's finalized post-quantum standards with classical cryptography in a hybrid configuration, protecting sensitive files against both contemporary and future quantum attacks (such as "Harvest Now, Decrypt Later" strategies).

This document serves as the complete operational guide for compiling, running, and managing both the CLI and Desktop GUI versions of QuantumVault.

---

## 🌟 Key Upgrades & Rust Advantages (vs. Python Prototype)

If you are transitioning from the Python prototype (`python_vault`), the Rust edition introduces massive improvements:

1. **Zero Native C Dependencies:** The Python prototype relied on compiling the C-based `liboqs` library via CMake and manual linking. QuantumVault Rust uses 100% pure Rust implementations of all algorithms (`fips203`, `fips204`, and `x25519-dalek`), meaning it compiles instantly with `cargo build` on any system.
2. **Chunked Streaming Encryption:** The Python tool loaded entire files into RAM, leading to crashes when handling files larger than system memory. The Rust edition processes files in **8 MiB chunks** via streams, allowing you to encrypt multi-gigabyte or terabyte files with minimal, constant RAM usage (~20-30 MB).
3. **Digital Signatures:** QuantumVault Rust implements **ML-DSA-65** signatures. The sender signs the encrypted container header, and the recipient verifies this signature before decryption. This guarantees **authenticity and non-repudiation**—preventing attackers from tampering with headers or spoofing the file source.
4. **Enforced Extension Handling:** The Tauri GUI automatically appends the `.qvault` extension during path selection or execution if omitted, avoiding path-saving issues on Windows.

---

## 🔑 Cryptographic Architecture

QuantumVault uses a **hybrid key encapsulation mechanism (KEM)** to establish keys, ensuring security is at least as strong as the strongest individual algorithm:

* **Classical KEM:** X25519 Elliptic Curve Diffie-Hellman (ECDH)
* **Post-Quantum KEM:** ML-KEM-1024 (FIPS 203)
* **Digital Signature:** ML-DSA-65 (FIPS 204)
* **Key Derivation:** HKDF-SHA3-256 (combining classical and post-quantum secrets)
* **Symmetric Encryption:** ChaCha20-Poly1305 (8 MiB chunks, each chunk utilizing a unique, derived nonce)

---

## 📂 Identity Folder & Key Management Structure

When you generate an identity, a directory is created containing the following layout:

```text
my_identity/
├── x25519_secret.bin      # Secret: Classical X25519 Private Key
├── ml_kem_dk.bin          # Secret: Post-quantum ML-KEM Decryption Key
├── ml_dsa_sk.bin          # Secret: Post-quantum ML-DSA Signing Key
│
├── encryption/            # Public: Share this folder with senders
│   ├── x25519_public.bin  # Classical X25519 Public Key
│   └── ml_kem_ek.bin      # Post-quantum ML-KEM Encapsulation Key
│
└── signing/               # Public: Share this folder with recipients
    └── ml_dsa_pk.bin      # Post-quantum ML-DSA Public Verification Key
```

> [!IMPORTANT]
> Keep your top-level secret files (`x25519_secret.bin`, `ml_kem_dk.bin`, `ml_dsa_sk.bin`) confidential and secure. Only share the `encryption/` or `signing/` directories with your communication partners.

---

## 💻 1. Command-Line Interface (CLI)

The CLI binary (`quantumvault-cli`) is a lightweight, zero-dependency utility optimized for server scripts, headless tasks, and automation.

### Compilation
Build the release profile using cargo:
```bash
cargo build --release -p quantumvault-cli
```
The compiled binary will be located at `target/release/quantumvault-cli.exe` (on Windows) or `target/release/quantumvault-cli` (on macOS/Linux).

---

### Step-by-Step CLI Walkthrough

In this scenario, **Alice** wants to encrypt `secret_report.pdf` and send it to **Bob**.

#### Step 1: Alice & Bob Generate Identities
Alice and Bob each generate their cryptographic identities:
```bash
# Alice generates her identity
cargo run -p quantumvault-cli -- keygen ./keys/alice

# Bob generates his identity
cargo run -p quantumvault-cli -- keygen ./keys/bob
```

#### Step 2: Bob Shares His Encryption Keys
Bob sends his public encryption directory (`./keys/bob/encryption`) to Alice.

#### Step 3: Alice Encrypts the File
Alice encrypts the file for Bob using:
* Her own identity folder (`./keys/alice`) to sign the container.
* Bob's public encryption folder (`./keys/bob/encryption`) to encapsulate the file key.

```bash
cargo run -p quantumvault-cli -- encrypt \
  -i secret_report.pdf \
  -o secret_report.pdf.qvault \
  -s ./keys/alice \
  -r ./keys/bob/encryption
```
This produces `secret_report.pdf.qvault`.

#### Step 4: Bob Decrypts the File
Alice sends `secret_report.pdf.qvault` and her public signing directory (`./keys/alice/signing`) to Bob. Bob decrypts the file using:
* His own identity folder (`./keys/bob`) containing his private keys.
* Alice's public signing folder (`./keys/alice/signing`) to verify her signature.

```bash
cargo run -p quantumvault-cli -- decrypt \
  -i secret_report.pdf.qvault \
  -o recovered_report.pdf \
  -r ./keys/bob \
  -s ./keys/alice/signing
```
The console will verify the signature validity and extract the decrypted file.

---

## 🖥️ 2. Desktop GUI Client (Tauri App)

The desktop client provides a high-contrast, professional-grade dark minimalistic user interface. The frontend is built using zero-dependency Vanilla HTML/CSS/JS, ensuring instant loads and no `node_modules` overhead.

### Compilation & Running

#### Active Toolchain Support
By default, the Tauri build configurations support Windows platforms. You can compile using either:
* **MSVC Toolchain (Default):**
  ```bash
  cargo run --bin quantumvault --features tauri
  ```
* **GNU Toolchain:** Recommended on systems resolving linker issues or when building with MinGW:
  ```bash
  rustup run stable-x86_64-pc-windows-gnu cargo run --bin quantumvault --features tauri
  ```

---

### GUI Step-by-Step Usage

#### 1. Generate an Identity
1. Launch the application.
2. In the **My Identity** section, click **Generate New**.
3. Choose a folder where your private and public keys should be saved.
4. The system will create the files and display a green confirmation message.

#### 2. Encrypting a File
1. Make sure you are on the **Encrypt** tab.
2. Under **Source File**, click **Browse** and select the file you want to protect.
3. Under **Output Vault (.qvault)**, click **Browse** to select where to save the encrypted archive. 
   *(Note: The UI will automatically ensure the output path ends with `.qvault` even if you do not type it).*
4. Under **My Identity (Sender)**, click **Select** and choose your own identity folder.
5. Under **Recipient Public Key (Encryption Dir)**, click **Select** and choose the recipient's public `encryption/` subfolder.
6. Click **Encrypt File**. The status bar will show "Processing... Please wait" followed by a success confirmation.

#### 3. Decrypting a File
1. Toggle to the **Decrypt** tab.
2. Under **Vault File**, browse to your encrypted `.qvault` archive.
3. Under **Output File**, browse to choose where you want to write the decrypted output file (including its target file extension, e.g. `.pdf` or `.zip`).
4. Under **Sender Public Key (Signing Dir)**, click **Select** and choose the sender's public `signing/` subfolder.
5. Under **My Identity (Recipient)**, click **Select** and choose your own identity folder.
6. Click **Decrypt File** to perform signature verification and decrypt the file.

---

## 🔍 Technical Details & Binary Specification

The `.qvault` container is formatted as a single file with a binary header followed by the encrypted payload chunks:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        QuantumVault Header Structure                   │
├──────────────────┬─────────────────┬───────────────────────────────────┤
│ Offset (Bytes)   │ Size (Bytes)    │ Content                           │
├──────────────────┼─────────────────┼───────────────────────────────────┤
│ 0 - 3            │ 4               │ Magic signature: [0x51,0x56,0x4C,0x54] ("QVLT")
│ 4 - 5            │ 2               │ Container Version (Big-Endian u16)│
│ 6 - 37           │ 32              │ Ephemeral X25519 Public Key       │
│ 38 - 1605        │ 1568            │ ML-KEM-1024 Ciphertext            │
│ 1606 - 4914      │ 3309            │ ML-DSA-65 Signature               │
│ 4915 - 4946      │ 32              │ Salt/Nonce Seed for HKDF          │
├──────────────────┴─────────────────┴───────────────────────────────────┤
│                    Encrypted Payload (ChaCha20-Poly1305)               │
├────────────────────────────────────────────────────────────────────────┤
│ Chunks of up to 8 MiB (8,388,608 bytes) plus 16 bytes auth tag.        │
│ Each chunk has its own unique derived key and nonce structure.          │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Troubleshooting

* **Compilation Errors / Missing Symbols on Windows (GNU):**
  If compiling Tauri on Windows with GNU target fails due to linker symbol limits, make sure the `crate-type` in `src-tauri/Cargo.toml` is configured to `["rlib"]` (not `["cdylib"]`).
* **Signature Verification Failed during Decryption:**
  Ensure you are using the correct sender's `signing/` folder. If the sender's public signing key (`ml_dsa_pk.bin`) does not match the private key used to sign the file, decryption will abort immediately to prevent spoofing.
* **Tauri Webview Blank Page:**
  Ensure you have run compile scripts from the root directory or that `devPath` / `distDir` in `src-tauri/tauri.conf.json` maps correctly to `../frontend`.

---

## ⚠️ Security Disclaimer

This software is an experimental implementation of FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA). It has **not** undergone a formal security audit. Do not use this tool to secure critical financial, military, or high-value infrastructure. Use it at your own risk.
