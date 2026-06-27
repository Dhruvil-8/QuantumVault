# Quickstart Guide

:::warning DISCLAIMER
This codebase is AI-generated and has not undergone security audits.
:::

This guide gets you up and running with the QuantumVault PQC SDK in under 5 minutes.

## 1. Installation

### Python
Install the package using pip (ensure you have Rust installed to compile Python bindings via Maturin):
```bash
pip install maturin
cd quantumvault-python
maturin develop
```

### CLI
Compile the command-line executable:
```bash
cargo build --release -p quantumvault-cli
```

---

## 2. Generate and Share Keys

### CLI
Generate a private `.qvk` key containing classical and PQ parameters:
```bash
quantumvault-cli keygen alice_secret.qvk --label "Alice Key"
```
Export your public key file to send to others:
```bash
quantumvault-cli export-public -s alice_secret.qvk -o alice_public.qvk
```

---

## 3. Secure File Locking

Encrypt a local file for a recipient using their public key:
```bash
quantumvault-cli encrypt -i secret.txt -o locked.qvf -s alice_secret.qvk -r bob_public.qvk
```

Decrypt the secure container back using your private key:
```bash
quantumvault-cli decrypt -i locked.qvf -o decrypted.txt -r bob_secret.qvk -s alice_public.qvk
```
