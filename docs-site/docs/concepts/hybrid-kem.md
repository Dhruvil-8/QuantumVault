# Hybrid Key Encapsulation (KEM)

:::warning DISCLAIMER
This codebase is AI-generated and has not undergone security audits.
:::

QuantumVault uses a **hybrid key encapsulation mechanism** to establish symmetric session keys. 

## The Core Concept
Instead of relying solely on newly standardized post-quantum algorithms (which lack decades of real-world cryptanalysis) or legacy elliptic curves (which are completely broken by Shor's algorithm on quantum computers), QuantumVault combines both:

1. **Classical Layer**: X25519 ECDH (RFC 7748).
2. **Post-Quantum Layer**: ML-KEM-1024 (FIPS 203).

## Key Combining via HKDF-SHA3-512
During encryption, the sender encapsulates secrets for both X25519 and ML-KEM-1024. The resulting shared secrets ($ss_{classical}$ and $ss_{pq}$) are concatenated and passed through a Key Derivation Function (KDF):

$$\text{Session Key} = \text{HKDF-SHA3-512}(ss_{classical} \mathbin{\Vert} ss_{pq})$$

This design guarantees that an attacker must break **both** X25519 and ML-KEM-1024 to compromise the session key. If either algorithm remains secure, the encrypted communication remains secure.
