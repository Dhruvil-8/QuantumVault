# Threat Model

:::warning DISCLAIMER
This codebase is AI-generated and has not undergone security audits.
:::

QuantumVault is designed to defend user files under specific cryptographic assumptions.

## In Scope (Protected Attacks)
- **Harvest Now, Decrypt Later**: Eavesdroppers recording traffic today to decrypt with future quantum computers running Shor's algorithm. ML-KEM-1024 protects KEM parameters.
- **Symmetric Key Compromise**: ChaCha20-Poly1305 authenticated encryption ensures that any alteration to the ciphertext causes decryption to fail.
- **Sender Spoofing**: ML-DSA-87 signatures ensure that files cannot be swapped or forged by a malicious sender once public keys are exchanged.
- **Symmetric Nonce Reuse**: Random 96-bit nonces generated for every encryption ensure that cryptanalysis based on nonce-reuse fails.

## Out of Scope (Unprotected Attacks)
- **Compromise of the Host Endpoint**: If the user's host OS is infected with spyware, keyloggers, or memory dump tools, active private keys could be harvested from RAM.
- **Phishing/Social Engineering**: Attackers tricking users into trust-accepting public keys of malicious actors.
- **Poor Key Storage Practices**: Storing `.qvk` keys unencrypted in public cloud storage.
