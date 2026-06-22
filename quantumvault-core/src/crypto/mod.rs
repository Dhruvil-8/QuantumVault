//! Cryptographic primitives for QuantumVault
//!
//! This module provides:
//! - ML-KEM-1024 (FIPS 203): Post-quantum key encapsulation
//! - ML-DSA-65 (FIPS 204): Post-quantum digital signatures
//! - X25519: Classical elliptic curve key exchange (hybrid layer)
//! - HKDF-SHA3-256: Key derivation function

pub mod identity;
pub mod kdf;
pub mod ml_dsa;
pub mod ml_kem;
pub mod public;
pub mod x25519;
