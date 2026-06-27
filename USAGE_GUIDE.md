# QuantumVault PQC SDK Operations & Usage Guide

> [!WARNING]
> **DISCLAIMER:** This repository is an AI-generated codebase. A professional third-party cryptographic, memory safety, or security audit has **not** been performed. While unit and integration test suites run successfully, this codebase has not undergone a formal security audit. Do not use this software in production systems or high-risk environments securing critical assets. Use it at your own risk.

QuantumVault is a high-performance, post-quantum secure file encryption locker and key manager. It integrates NIST's finalized post-quantum standards with classical cryptography in a hybrid configuration, protecting sensitive files against both contemporary and future quantum attacks (such as "Harvest Now, Decrypt Later" strategies).

---

## 1. Command-Line Interface (CLI)

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
Alice and Bob each generate their cryptographic identities (secret key files ending in `.qvk`):
```bash
# Alice generates her identity with label and comment metadata
quantumvault-cli keygen alice_secret.qvk --label "Alice Key" --comment "Alice PQC Identity"

# Bob generates his identity
quantumvault-cli keygen bob_secret.qvk --label "Bob Key"
```

#### Step 2: Bob Exports and Shares His Public Key
Bob exports his public key from his secret key and shares `bob_public.qvk` with Alice:
```bash
quantumvault-cli export-public -s bob_secret.qvk -o bob_public.qvk
```

#### Step 3: Alice Encrypts the File
Alice encrypts the file for Bob using:
- Her own secret key file (`alice_secret.qvk`) to sign the envelope.
- Bob's public key file (`bob_public.qvk`) to encapsulate the file key.

```bash
quantumvault-cli encrypt \
  -i secret_report.pdf \
  -o secret_report.pdf.qvf \
  -s alice_secret.qvk \
  -r bob_public.qvk
```

#### Step 4: Bob Decrypts the File
Alice sends `secret_report.pdf.qvf` and her public key file (`alice_public.qvk`) to Bob. Bob decrypts the file using:
- His secret key file (`bob_secret.qvk`) to decapsulate.
- Alice's public key file (`alice_public.qvk`) to verify her signature.

```bash
quantumvault-cli decrypt \
  -i secret_report.pdf.qvf \
  -o secret_report_decrypted.pdf \
  -r bob_secret.qvk \
  -s alice_public.qvk
```

---

## 2. Desktop GUI Client

The GUI client (`quantumvault-gui`) offers a native, GPU-rendered desktop application built with `egui` and `eframe`. It allows key generation, metadata management, and file encryption/decryption via interactive dialogs.

### Compilation
Build the release profile:
```bash
cargo build --release -p quantumvault-gui
```
Run the client:
```bash
cargo run -p quantumvault-gui --release
```

### Key GUI Features
1. **Interactive File Picking**: Clicking `Select File` opens the native OS file picker (powered by `rfd`) to load secret keys (`.qvk`), public keys (`.qvk`), or envelope files (`.qvf`).
2. **Metadata View**: Displays key labels, comments, creation timestamps, and active algorithms directly in the user interface.
3. **Base64 Key Sharing**: Allows users to quickly copy and share base64 public key strings without creating files.
4. **Drag-and-Drop / Form Actions**: Prompts for file output paths and appends correct extensions (`.qvk`/`.qvf`) automatically.
