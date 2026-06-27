# QuantumVault PQC SDK — Full Agent Implementation Plan

> **Purpose**: This document is a complete, self-contained instruction set for an autonomous AI agent to implement the QuantumVault Post-Quantum Cryptography SDK from scratch. Every section contains exact file paths, exact code, exact commands, and explicit success criteria. The agent must not skip steps or assume context not present in this document.

---

## 0. Prerequisites & Environment

### 0.1 Required Toolchain
```bash
# Install Rust (stable + nightly for some proc-macros)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install stable
rustup toolchain install nightly
rustup target add wasm32-unknown-unknown

# Install wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

# Install Python 3.10+ and maturin (for pyo3 bindings)
pip install maturin twine

# Install Node.js 18+ and napi tools
npm install -g @napi-rs/cli

# Install cbindgen (for C header generation)
cargo install cbindgen

# Install cargo tools
cargo install cargo-audit cargo-deny cargo-tarpaulin cargo-criterion
```

### 0.2 Repository Initialisation
```bash
# Create Cargo workspace
mkdir quantumvault-sdk && cd quantumvault-sdk
git init

cat > Cargo.toml << 'EOF'
[workspace]
members = [
    "quantumvault-core",
    "quantumvault-cli",
    "quantumvault-python",
    "quantumvault-wasm",
    "quantumvault-ffi",
]
resolver = "2"

[workspace.dependencies]
# PQC primitives
pqcrypto-mlkem    = "0.1"
pqcrypto-mldsa    = "0.1"
pqcrypto-traits   = "0.3"

# Classical crypto
x25519-dalek      = { version = "2", features = ["static_secrets"] }
chacha20poly1305  = "0.10"
hkdf              = "0.12"
sha3              = "0.10"
rand              = { version = "0.8", features = ["getrandom"] }
rand_core         = "0.6"
getrandom         = { version = "0.2", features = ["js"] }

# Serialisation
serde             = { version = "1", features = ["derive"] }
serde_json        = "1"
bincode           = "1"
base64            = "0.22"
hex               = "0.4"

# Error handling
thiserror         = "1"
anyhow            = "1"

# Zeroize (secure memory erasure)
zeroize           = { version = "1", features = ["derive"] }

# Time
chrono            = { version = "0.4", features = ["serde"] }

[profile.release]
opt-level         = 3
lto               = true
codegen-units     = 1
strip             = "symbols"
EOF
```

---

## 1. Phase 1 — `quantumvault-core`

> **Goal**: A pure Rust crate implementing all cryptographic primitives with a clean, opinionated public API. No GUI, no CLI, no FFI concerns. This is the single source of truth for all crypto logic.

### 1.1 Crate Structure
```
quantumvault-core/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Public API surface — re-exports only
│   ├── error.rs            # QVError enum
│   ├── keys/
│   │   ├── mod.rs
│   │   ├── identity.rs     # PQIdentity (keypair generation + serialisation)
│   │   ├── format.rs       # QVKey binary format v1 spec
│   │   └── migration.rs    # Classical → hybrid key migration helpers
│   ├── kem/
│   │   ├── mod.rs
│   │   └── hybrid.rs       # X25519 + ML-KEM-1024 hybrid encapsulation
│   ├── sign/
│   │   ├── mod.rs
│   │   └── hybrid.rs       # Ed25519 + ML-DSA-87 hybrid signing
│   ├── sym/
│   │   ├── mod.rs
│   │   └── aead.rs         # ChaCha20-Poly1305 AEAD wrapper
│   ├── kdf/
│   │   ├── mod.rs
│   │   └── hkdf.rs         # HKDF-SHA3-512 wrapper
│   ├── session/
│   │   ├── mod.rs
│   │   └── ratchet.rs      # PQSession — stateful messaging session
│   ├── file/
│   │   ├── mod.rs
│   │   └── envelope.rs     # PQFile — encrypt/decrypt/sign file blobs
│   └── constants.rs        # All magic numbers, version bytes, domain seps
├── tests/
│   ├── kat_mlkem.rs        # NIST KAT vectors for ML-KEM-1024
│   ├── kat_mldsa.rs        # NIST KAT vectors for ML-DSA-87
│   ├── roundtrip.rs        # Full encrypt → decrypt roundtrips
│   ├── session.rs          # Session ratchet tests
│   └── file.rs             # File envelope tests
└── benches/
    └── crypto.rs           # Criterion benchmarks
```

### 1.2 `quantumvault-core/Cargo.toml`
```toml
[package]
name          = "quantumvault-core"
version       = "0.1.0"
edition       = "2021"
rust-version  = "1.75"
authors       = ["Dhruvil <dhruvil@quantumvault.dev>"]
description   = "Post-quantum cryptography SDK core — hybrid PQC primitives"
license       = "MIT OR Apache-2.0"
repository    = "https://github.com/Dhruvil-8/quantumvault-sdk"
keywords      = ["post-quantum", "cryptography", "ml-kem", "ml-dsa", "pqc"]
categories    = ["cryptography", "no-std"]

[dependencies]
pqcrypto-mlkem   = { workspace = true }
pqcrypto-mldsa   = { workspace = true }
pqcrypto-traits  = { workspace = true }
x25519-dalek     = { workspace = true }
chacha20poly1305 = { workspace = true }
hkdf             = { workspace = true }
sha3             = { workspace = true }
rand             = { workspace = true }
rand_core        = { workspace = true }
serde            = { workspace = true }
bincode          = { workspace = true }
base64           = { workspace = true }
hex              = { workspace = true }
thiserror        = { workspace = true }
zeroize          = { workspace = true }
chrono           = { workspace = true }

[dev-dependencies]
anyhow         = { workspace = true }
criterion      = { version = "0.5", features = ["html_reports"] }

[[bench]]
name    = "crypto"
harness = false
```

### 1.3 `src/constants.rs` — All Magic Values
```rust
//! Protocol constants. All version bytes, domain separators, and size limits
//! are defined here. Never hardcode these elsewhere.

/// QVKey binary format version
pub const QVKEY_VERSION: u8 = 0x01;

/// Magic header for QVKey serialised blobs: b"QVK"
pub const QVKEY_MAGIC: [u8; 3] = [0x51, 0x56, 0x4B];

/// Magic header for QVCiphertext blobs: b"QVC"
pub const QVCIPHERTEXT_MAGIC: [u8; 3] = [0x51, 0x56, 0x43];

/// Magic header for QVSignature blobs: b"QVS"
pub const QVSIGNATURE_MAGIC: [u8; 3] = [0x51, 0x56, 0x53];

/// Magic header for QVFile envelope blobs: b"QVF"
pub const QVFILE_MAGIC: [u8; 3] = [0x51, 0x56, 0x46];

/// HKDF domain separators — prevent cross-protocol key reuse
pub const HKDF_INFO_KEM:      &[u8] = b"QV1-KEM-SHARED-SECRET-v1";
pub const HKDF_INFO_SESSION:  &[u8] = b"QV1-SESSION-KEY-v1";
pub const HKDF_INFO_FILE:     &[u8] = b"QV1-FILE-KEY-v1";
pub const HKDF_INFO_IDENTITY: &[u8] = b"QV1-IDENTITY-KEY-v1";

/// Key sizes
pub const X25519_SECRET_KEY_SIZE:    usize = 32;
pub const X25519_PUBLIC_KEY_SIZE:    usize = 32;
pub const CHACHA20_KEY_SIZE:         usize = 32;
pub const CHACHA20_NONCE_SIZE:       usize = 12;
pub const HKDF_SHA3_512_OUTPUT_SIZE: usize = 64;

/// ML-KEM-1024 sizes (NIST FIPS 203)
pub const MLKEM1024_PUBLIC_KEY_SIZE:     usize = 1568;
pub const MLKEM1024_SECRET_KEY_SIZE:     usize = 3168;
pub const MLKEM1024_CIPHERTEXT_SIZE:     usize = 1568;
pub const MLKEM1024_SHARED_SECRET_SIZE:  usize = 32;

/// ML-DSA-87 sizes (NIST FIPS 204)
pub const MLDSA87_PUBLIC_KEY_SIZE:  usize = 2592;
pub const MLDSA87_SECRET_KEY_SIZE:  usize = 4896;
pub const MLDSA87_SIGNATURE_SIZE:   usize = 4627;

/// Maximum file size for single-pass encryption: 4 GiB
pub const MAX_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Session nonce counter maximum before rekeying is mandatory
pub const SESSION_REKEY_THRESHOLD: u64 = 1_000_000;
```

### 1.4 `src/error.rs`
```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum QVError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Encapsulation failed: {0}")]
    Encapsulation(String),

    #[error("Decapsulation failed: {0}")]
    Decapsulation(String),

    #[error("Signing failed: {0}")]
    Signing(String),

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed — ciphertext is corrupt or key is wrong")]
    DecryptionFailed,

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Key version mismatch: expected {expected}, got {got}")]
    KeyVersionMismatch { expected: u8, got: u8 },

    #[error("Invalid magic header: expected {expected:?}, got {got:?}")]
    InvalidMagic { expected: [u8; 3], got: [u8; 3] },

    #[error("Serialisation error: {0}")]
    Serialisation(String),

    #[error("Deserialisation error: {0}")]
    Deserialisation(String),

    #[error("File too large: {size} bytes exceeds maximum {max} bytes")]
    FileTooLarge { size: u64, max: u64 },

    #[error("Session nonce exhausted — rekey required")]
    NonceExhausted,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

pub type QVResult<T> = Result<T, QVError>;
```

### 1.5 `src/keys/format.rs` — QVKey Binary Format v1

**This is the canonical key serialisation format. All bindings must use this.**

```
QVKey v1 Binary Layout
=======================
Offset  Size  Field
------  ----  -----
0       3     Magic: [0x51, 0x56, 0x4B]  ("QVK")
3       1     Version: 0x01
4       1     KeyType:
                0x01 = HybridPublicKey  (X25519 + ML-KEM-1024 + ML-DSA-87 pub)
                0x02 = HybridSecretKey  (X25519 + ML-KEM-1024 + ML-DSA-87 sec)
                0x03 = SigningPublicKey (ML-DSA-87 pub only)
                0x04 = SigningSecretKey (ML-DSA-87 sec only)
5       8     CreatedAt: Unix timestamp u64 little-endian
13      2     MetaLen: length of metadata JSON u16 little-endian
15      N     Meta: UTF-8 JSON (label, comment, expiry — all optional)
15+N    4     PayloadLen: u32 little-endian
19+N    M     Payload: key material bytes (layout depends on KeyType)
19+N+M  32    BLAKE3 checksum of bytes [0 .. 19+N+M-1]

KeyType 0x01 Payload Layout (HybridPublicKey, M = 32 + 1568 + 2592 = 4192):
  [0  ..  31]  X25519 public key (32 bytes)
  [32 .. 1599] ML-KEM-1024 public key (1568 bytes)
  [1600.. 4191] ML-DSA-87 public key (2592 bytes)

KeyType 0x02 Payload Layout (HybridSecretKey, M = 32 + 3168 + 4896 = 8096):
  [0  ..  31]  X25519 secret key (32 bytes)
  [32 .. 3199] ML-KEM-1024 secret key (3168 bytes)
  [3200..8095] ML-DSA-87 secret key (4896 bytes)
```

```rust
// src/keys/format.rs

use crate::constants::*;
use crate::error::{QVError, QVResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyType {
    HybridPublic  = 0x01,
    HybridSecret  = 0x02,
    SigningPublic  = 0x03,
    SigningSecret  = 0x04,
}

impl TryFrom<u8> for KeyType {
    type Error = QVError;
    fn try_from(v: u8) -> QVResult<Self> {
        match v {
            0x01 => Ok(Self::HybridPublic),
            0x02 => Ok(Self::HybridSecret),
            0x03 => Ok(Self::SigningPublic),
            0x04 => Ok(Self::SigningSecret),
            other => Err(QVError::InvalidKeyFormat(format!("unknown KeyType byte: {other:#04x}"))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeyMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,  // Unix timestamp
}

/// Serialise key material into QVKey v1 binary format.
/// `payload` is the raw key bytes. `checksum_fn` accepts all bytes
/// before checksum and returns 32-byte BLAKE3 digest.
pub fn encode_qvkey(
    key_type: KeyType,
    meta: &KeyMeta,
    payload: &[u8],
) -> QVResult<Vec<u8>> {
    let meta_json = serde_json::to_vec(meta)
        .map_err(|e| QVError::Serialisation(e.to_string()))?;
    if meta_json.len() > u16::MAX as usize {
        return Err(QVError::Serialisation("metadata too large".into()));
    }
    let created_at = Utc::now().timestamp() as u64;

    let mut buf = Vec::with_capacity(19 + meta_json.len() + payload.len() + 32);
    buf.extend_from_slice(&QVKEY_MAGIC);
    buf.push(QVKEY_VERSION);
    buf.push(key_type as u8);
    buf.extend_from_slice(&created_at.to_le_bytes());
    buf.extend_from_slice(&(meta_json.len() as u16).to_le_bytes());
    buf.extend_from_slice(&meta_json);
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);

    // BLAKE3 checksum
    let hash = blake3::hash(&buf);
    buf.extend_from_slice(hash.as_bytes());

    Ok(buf)
}

pub struct DecodedQVKey {
    pub key_type:   KeyType,
    pub created_at: u64,
    pub meta:       KeyMeta,
    pub payload:    Vec<u8>,
}

pub fn decode_qvkey(data: &[u8]) -> QVResult<DecodedQVKey> {
    if data.len() < 19 + 32 {
        return Err(QVError::InvalidKeyFormat("buffer too short".into()));
    }

    // Magic
    let magic: [u8; 3] = data[0..3].try_into().unwrap();
    if magic != QVKEY_MAGIC {
        return Err(QVError::InvalidMagic { expected: QVKEY_MAGIC, got: magic });
    }

    // Version
    let version = data[3];
    if version != QVKEY_VERSION {
        return Err(QVError::KeyVersionMismatch { expected: QVKEY_VERSION, got: version });
    }

    let key_type = KeyType::try_from(data[4])?;
    let created_at = u64::from_le_bytes(data[5..13].try_into().unwrap());
    let meta_len = u16::from_le_bytes(data[13..15].try_into().unwrap()) as usize;

    let meta_start = 15;
    let meta_end   = meta_start + meta_len;
    if data.len() < meta_end + 4 {
        return Err(QVError::InvalidKeyFormat("truncated at meta".into()));
    }

    let meta: KeyMeta = serde_json::from_slice(&data[meta_start..meta_end])
        .map_err(|e| QVError::Deserialisation(e.to_string()))?;

    let payload_len = u32::from_le_bytes(data[meta_end..meta_end+4].try_into().unwrap()) as usize;
    let payload_start = meta_end + 4;
    let payload_end   = payload_start + payload_len;

    if data.len() < payload_end + 32 {
        return Err(QVError::InvalidKeyFormat("truncated at payload".into()));
    }

    // Verify checksum
    let expected_hash = blake3::hash(&data[..payload_end]);
    let stored_hash = &data[payload_end..payload_end + 32];
    if expected_hash.as_bytes() != stored_hash {
        return Err(QVError::InvalidKeyFormat("checksum mismatch — key is corrupt".into()));
    }

    Ok(DecodedQVKey {
        key_type,
        created_at,
        meta,
        payload: data[payload_start..payload_end].to_vec(),
    })
}
```

> **Agent note**: Add `blake3 = "1"` to `quantumvault-core/Cargo.toml` dependencies.

### 1.6 `src/keys/identity.rs` — PQIdentity
```rust
// src/keys/identity.rs

use crate::constants::*;
use crate::error::{QVError, QVResult};
use crate::keys::format::{encode_qvkey, decode_qvkey, KeyMeta, KeyType};
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_mldsa::mldsa87;
use pqcrypto_traits::kem::{PublicKey as KemPK, SecretKey as KemSK};
use pqcrypto_traits::sign::{PublicKey as SignPK, SecretKey as SignSK};
use rand_core::OsRng;
use x25519_dalek::{PublicKey as X25519PK, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A complete hybrid keypair: X25519 + ML-KEM-1024 (for KEM) + ML-DSA-87 (for signing).
/// The secret key material is zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct PQIdentity {
    // KEM keys
    pub(crate) x25519_secret:    StaticSecret,
    pub(crate) x25519_public:    X25519PK,
    pub(crate) mlkem_public:     mlkem1024::PublicKey,
    #[zeroize(skip)]
    mlkem_secret:                mlkem1024::SecretKey,

    // Signing keys
    #[zeroize(skip)]
    pub(crate) mldsa_public:     mldsa87::PublicKey,
    #[zeroize(skip)]
    mldsa_secret:                mldsa87::SecretKey,

    pub meta: KeyMeta,
}

impl PQIdentity {
    /// Generate a new random identity.
    pub fn generate() -> QVResult<Self> {
        Self::generate_with_meta(KeyMeta::default())
    }

    pub fn generate_with_meta(meta: KeyMeta) -> QVResult<Self> {
        // X25519
        let x25519_secret = StaticSecret::random_from_rng(OsRng);
        let x25519_public = X25519PK::from(&x25519_secret);

        // ML-KEM-1024
        let (mlkem_public, mlkem_secret) = mlkem1024::keypair();

        // ML-DSA-87
        let (mldsa_public, mldsa_secret) = mldsa87::keypair();

        Ok(Self {
            x25519_secret,
            x25519_public,
            mlkem_public,
            mlkem_secret,
            mldsa_public,
            mldsa_secret,
            meta,
        })
    }

    /// Export the public key bundle as QVKey v1 bytes.
    /// Safe to share publicly.
    pub fn export_public(&self) -> QVResult<Vec<u8>> {
        let mut payload = Vec::with_capacity(
            X25519_PUBLIC_KEY_SIZE + MLKEM1024_PUBLIC_KEY_SIZE + MLDSA87_PUBLIC_KEY_SIZE
        );
        payload.extend_from_slice(self.x25519_public.as_bytes());
        payload.extend_from_slice(self.mlkem_public.as_bytes());
        payload.extend_from_slice(self.mldsa_public.as_bytes());
        encode_qvkey(KeyType::HybridPublic, &self.meta, &payload)
    }

    /// Export the secret key bundle as QVKey v1 bytes.
    /// Store encrypted at rest. Never transmit.
    pub fn export_secret(&self) -> QVResult<Vec<u8>> {
        let mut payload = Vec::with_capacity(
            X25519_SECRET_KEY_SIZE + MLKEM1024_SECRET_KEY_SIZE + MLDSA87_SECRET_KEY_SIZE
        );
        payload.extend_from_slice(self.x25519_secret.as_bytes());
        payload.extend_from_slice(self.mlkem_secret.as_bytes());
        payload.extend_from_slice(self.mldsa_secret.as_bytes());
        let result = encode_qvkey(KeyType::HybridSecret, &self.meta, &payload);
        payload.zeroize();
        result
    }

    /// Export public key as Base64 string (for easy copy-paste / API transport).
    pub fn export_public_b64(&self) -> QVResult<String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        Ok(STANDARD.encode(self.export_public()?))
    }

    /// Load identity from exported secret key bytes.
    pub fn from_secret_bytes(data: &[u8]) -> QVResult<Self> {
        let decoded = decode_qvkey(data)?;
        if decoded.key_type != KeyType::HybridSecret {
            return Err(QVError::InvalidKeyFormat("expected HybridSecret key".into()));
        }

        let expected_len = X25519_SECRET_KEY_SIZE + MLKEM1024_SECRET_KEY_SIZE + MLDSA87_SECRET_KEY_SIZE;
        if decoded.payload.len() != expected_len {
            return Err(QVError::InvalidKeyFormat(
                format!("payload size mismatch: expected {expected_len}, got {}", decoded.payload.len())
            ));
        }

        let mut offset = 0;

        // X25519
        let x25519_bytes: [u8; 32] = decoded.payload[offset..offset+32].try_into().unwrap();
        let x25519_secret = StaticSecret::from(x25519_bytes);
        let x25519_public = X25519PK::from(&x25519_secret);
        offset += 32;

        // ML-KEM-1024
        let mlkem_secret = mlkem1024::SecretKey::from_bytes(&decoded.payload[offset..offset+MLKEM1024_SECRET_KEY_SIZE])
            .map_err(|e| QVError::InvalidKeyFormat(format!("ML-KEM secret: {e:?}")))?;
        // Reconstruct public key from secret (pqcrypto crate provides this)
        let mlkem_public_bytes = &decoded.payload[offset + MLKEM1024_SECRET_KEY_SIZE - MLKEM1024_PUBLIC_KEY_SIZE..];
        // Note: ML-KEM secret key in NIST format embeds the public key in last 1568 bytes
        let mlkem_public = mlkem1024::PublicKey::from_bytes(
            &decoded.payload[offset + MLKEM1024_SECRET_KEY_SIZE - MLKEM1024_PUBLIC_KEY_SIZE
                ..offset + MLKEM1024_SECRET_KEY_SIZE]
        ).map_err(|e| QVError::InvalidKeyFormat(format!("ML-KEM public: {e:?}")))?;
        offset += MLKEM1024_SECRET_KEY_SIZE;

        // ML-DSA-87
        let mldsa_secret = mldsa87::SecretKey::from_bytes(&decoded.payload[offset..offset+MLDSA87_SECRET_KEY_SIZE])
            .map_err(|e| QVError::InvalidKeyFormat(format!("ML-DSA secret: {e:?}")))?;
        let mldsa_public = mldsa87::PublicKey::from_bytes(&decoded.payload[offset..offset+MLDSA87_PUBLIC_KEY_SIZE])
            .map_err(|e| QVError::InvalidKeyFormat(format!("ML-DSA public: {e:?}")))?;

        Ok(Self {
            x25519_secret,
            x25519_public,
            mlkem_public,
            mlkem_secret,
            mldsa_public,
            mldsa_secret,
            meta: decoded.meta,
        })
    }
}

/// Public-key-only view for recipients (no secret material).
pub struct PQPublicKey {
    pub x25519_public: X25519PK,
    pub mlkem_public:  mlkem1024::PublicKey,
    pub mldsa_public:  mldsa87::PublicKey,
    pub meta:          KeyMeta,
}

impl PQPublicKey {
    pub fn from_bytes(data: &[u8]) -> QVResult<Self> {
        let decoded = decode_qvkey(data)?;
        if decoded.key_type != KeyType::HybridPublic {
            return Err(QVError::InvalidKeyFormat("expected HybridPublic key".into()));
        }

        let expected = X25519_PUBLIC_KEY_SIZE + MLKEM1024_PUBLIC_KEY_SIZE + MLDSA87_PUBLIC_KEY_SIZE;
        if decoded.payload.len() != expected {
            return Err(QVError::InvalidKeyFormat("payload size mismatch".into()));
        }

        let x25519_bytes: [u8; 32] = decoded.payload[0..32].try_into().unwrap();
        let x25519_public = X25519PK::from(x25519_bytes);

        let mlkem_public = mlkem1024::PublicKey::from_bytes(&decoded.payload[32..32+MLKEM1024_PUBLIC_KEY_SIZE])
            .map_err(|e| QVError::InvalidKeyFormat(format!("{e:?}")))?;

        let mldsa_public = mldsa87::PublicKey::from_bytes(
            &decoded.payload[32+MLKEM1024_PUBLIC_KEY_SIZE..]
        ).map_err(|e| QVError::InvalidKeyFormat(format!("{e:?}")))?;

        Ok(Self { x25519_public, mlkem_public, mldsa_public, meta: decoded.meta })
    }

    pub fn from_b64(s: &str) -> QVResult<Self> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let bytes = STANDARD.decode(s)
            .map_err(|e| QVError::Deserialisation(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}
```

### 1.7 `src/kem/hybrid.rs` — Hybrid KEM
```rust
// src/kem/hybrid.rs
//
// Hybrid key encapsulation: X25519 + ML-KEM-1024.
// Both shared secrets are combined via HKDF-SHA3-512.
// Neither classical nor PQ alone is sufficient — attacker must break both.

use crate::constants::*;
use crate::error::{QVError, QVResult};
use crate::kdf::hkdf::hkdf_sha3_512;
use crate::keys::identity::{PQIdentity, PQPublicKey};
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};
use rand_core::OsRng;
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

/// Output of encapsulation: the shared secret + ciphertext to send to recipient.
pub struct KemResult {
    /// 32-byte symmetric key derived from hybrid shared secret. Zeroized on drop.
    pub shared_key: Zeroizing<[u8; 32]>,
    /// Bytes to send to recipient so they can derive the same shared_key.
    /// Layout: [x25519_ephemeral_pub (32)] ++ [mlkem_ciphertext (1568)]
    pub ciphertext: Vec<u8>,
}

/// Encapsulate using recipient's public key.
/// Returns a KemResult — send `ciphertext` to recipient, use `shared_key` for AEAD.
pub fn encapsulate(recipient: &PQPublicKey) -> QVResult<KemResult> {
    // === X25519 ===
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);
    let x25519_ss: [u8; 32] = ephemeral_secret.diffie_hellman(&recipient.x25519_public).to_bytes();

    // === ML-KEM-1024 ===
    let (mlkem_ss, mlkem_ct) = mlkem1024::encapsulate(&recipient.mlkem_public);

    // === Combine via HKDF-SHA3-512 ===
    // IKM = x25519_ss || mlkem_ss (64 bytes total)
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(&x25519_ss);
    ikm[32..].copy_from_slice(mlkem_ss.as_bytes());

    // Salt = x25519_ephemeral_pub || mlkem_ciphertext (prevents KEM mixing attacks)
    let mut salt = Vec::with_capacity(32 + MLKEM1024_CIPHERTEXT_SIZE);
    salt.extend_from_slice(ephemeral_public.as_bytes());
    salt.extend_from_slice(mlkem_ct.as_bytes());

    let derived = hkdf_sha3_512(ikm.as_ref(), Some(&salt), HKDF_INFO_KEM, 32)?;
    let mut shared_key = Zeroizing::new([0u8; 32]);
    shared_key.copy_from_slice(&derived);

    // Ciphertext to send
    let mut ciphertext = Vec::with_capacity(32 + MLKEM1024_CIPHERTEXT_SIZE);
    ciphertext.extend_from_slice(ephemeral_public.as_bytes());
    ciphertext.extend_from_slice(mlkem_ct.as_bytes());

    Ok(KemResult { shared_key, ciphertext })
}

/// Decapsulate using our own secret key.
pub fn decapsulate(identity: &PQIdentity, ciphertext: &[u8]) -> QVResult<Zeroizing<[u8; 32]>> {
    if ciphertext.len() != 32 + MLKEM1024_CIPHERTEXT_SIZE {
        return Err(QVError::Decapsulation(format!(
            "ciphertext length mismatch: expected {}, got {}",
            32 + MLKEM1024_CIPHERTEXT_SIZE,
            ciphertext.len()
        )));
    }

    // === X25519 ===
    let ephemeral_pub_bytes: [u8; 32] = ciphertext[..32].try_into().unwrap();
    let ephemeral_pub = x25519_dalek::PublicKey::from(ephemeral_pub_bytes);
    let x25519_ss: [u8; 32] = identity.x25519_secret.diffie_hellman(&ephemeral_pub).to_bytes();

    // === ML-KEM-1024 ===
    let mlkem_ct = mlkem1024::Ciphertext::from_bytes(&ciphertext[32..])
        .map_err(|e| QVError::Decapsulation(format!("{e:?}")))?;
    let mlkem_ss = mlkem1024::decapsulate(&mlkem_ct, &identity.mlkem_secret);

    // === Combine via HKDF-SHA3-512 ===
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(&x25519_ss);
    ikm[32..].copy_from_slice(mlkem_ss.as_bytes());

    let derived = hkdf_sha3_512(ikm.as_ref(), Some(ciphertext), HKDF_INFO_KEM, 32)?;
    let mut shared_key = Zeroizing::new([0u8; 32]);
    shared_key.copy_from_slice(&derived);

    Ok(shared_key)
}
```

### 1.8 `src/kdf/hkdf.rs`
```rust
use crate::error::{QVError, QVResult};
use hkdf::Hkdf;
use sha3::Sha3_512;

/// HKDF-SHA3-512 with explicit info binding.
/// Always use a unique HKDF_INFO_* constant per usage context.
pub fn hkdf_sha3_512(
    ikm:    &[u8],
    salt:   Option<&[u8]>,
    info:   &[u8],
    length: usize,
) -> QVResult<Vec<u8>> {
    let hk = Hkdf::<Sha3_512>::new(salt, ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|_| QVError::Unknown("HKDF expand failed — requested length too long".into()))?;
    Ok(okm)
}
```

### 1.9 `src/sym/aead.rs`
```rust
use crate::error::{QVError, QVResult};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};

/// Encrypt plaintext with a 32-byte key.
/// Returns: [nonce (12 bytes)] ++ [ciphertext + tag]
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> QVResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce  = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher.encrypt(&nonce, plaintext)
        .map_err(|e| QVError::Encryption(e.to_string()))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt ciphertext produced by `encrypt`.
pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> QVResult<Vec<u8>> {
    if ciphertext.len() < 12 {
        return Err(QVError::DecryptionFailed);
    }
    let nonce  = Nonce::from_slice(&ciphertext[..12]);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(nonce, &ciphertext[12..])
        .map_err(|_| QVError::DecryptionFailed)
}
```

### 1.10 `src/sign/hybrid.rs`
```rust
use crate::error::{QVError, QVResult};
use crate::keys::identity::{PQIdentity, PQPublicKey};
use pqcrypto_mldsa::mldsa87;
use pqcrypto_traits::sign::{DetachedSignature, SignedMessage};
use sha3::{Digest, Sha3_256};

/// Sign arbitrary bytes. Returns ML-DSA-87 detached signature bytes.
/// The message is pre-hashed with SHA3-256 to support large payloads.
pub fn sign(identity: &PQIdentity, message: &[u8]) -> QVResult<Vec<u8>> {
    let hash = Sha3_256::digest(message);
    let sig  = mldsa87::detached_sign(&hash, &identity.mldsa_secret);
    Ok(sig.as_bytes().to_vec())
}

/// Verify a detached signature produced by `sign`.
pub fn verify(public_key: &PQPublicKey, message: &[u8], signature: &[u8]) -> QVResult<()> {
    let hash = Sha3_256::digest(message);
    let sig  = mldsa87::DetachedSignature::from_bytes(signature)
        .map_err(|_| QVError::InvalidKeyFormat("invalid signature bytes".into()))?;
    mldsa87::verify_detached_signature(&sig, &hash, &public_key.mldsa_public)
        .map_err(|_| QVError::VerificationFailed)
}
```

### 1.11 `src/file/envelope.rs` — PQFile High-Level API

**This is the primary user-facing API for file encryption.**

```rust
// QVFile envelope layout:
// [MAGIC 3] [VERSION 1] [KEM_CT_LEN 4 LE] [KEM_CT N] [SIG_LEN 4 LE] [SIG M]
// [AEAD_CT_LEN 8 LE] [AEAD_CT P]

use crate::constants::*;
use crate::error::{QVError, QVResult};
use crate::kem::hybrid::{encapsulate, decapsulate};
use crate::sign::hybrid::{sign, verify};
use crate::sym::aead::{encrypt, decrypt};
use crate::keys::identity::{PQIdentity, PQPublicKey};

pub struct PQFile;

impl PQFile {
    /// Encrypt `plaintext` for `recipient` and sign with `sender`.
    /// Returns a self-contained envelope blob.
    pub fn encrypt_and_sign(
        plaintext: &[u8],
        recipient: &PQPublicKey,
        sender:    &PQIdentity,
    ) -> QVResult<Vec<u8>> {
        if plaintext.len() as u64 > MAX_FILE_SIZE {
            return Err(QVError::FileTooLarge {
                size: plaintext.len() as u64,
                max:  MAX_FILE_SIZE,
            });
        }

        // 1. KEM: derive shared key + KEM ciphertext
        let kem = encapsulate(recipient)?;
        let shared_key: [u8; 32] = *kem.shared_key;

        // 2. Sign the plaintext
        let signature = sign(sender, plaintext)?;

        // 3. AEAD encrypt
        let aead_ct = encrypt(&shared_key, plaintext)?;

        // 4. Assemble envelope
        let mut env = Vec::new();
        env.extend_from_slice(&QVFILE_MAGIC);
        env.push(QVKEY_VERSION);

        env.extend_from_slice(&(kem.ciphertext.len() as u32).to_le_bytes());
        env.extend_from_slice(&kem.ciphertext);

        env.extend_from_slice(&(signature.len() as u32).to_le_bytes());
        env.extend_from_slice(&signature);

        env.extend_from_slice(&(aead_ct.len() as u64).to_le_bytes());
        env.extend_from_slice(&aead_ct);

        Ok(env)
    }

    /// Decrypt a PQFile envelope using `recipient_identity`.
    /// Optionally verify sender's signature if `sender_public` is provided.
    pub fn decrypt_and_verify(
        envelope:         &[u8],
        recipient:        &PQIdentity,
        sender_public:    Option<&PQPublicKey>,
    ) -> QVResult<Vec<u8>> {
        let mut offset = 0;

        // Magic + version
        if envelope.len() < 4 { return Err(QVError::InvalidKeyFormat("envelope too short".into())); }
        let magic: [u8; 3] = envelope[0..3].try_into().unwrap();
        if magic != QVFILE_MAGIC {
            return Err(QVError::InvalidMagic { expected: QVFILE_MAGIC, got: magic });
        }
        offset += 4; // magic + version

        // KEM ciphertext
        let kem_ct_len = u32::from_le_bytes(envelope[offset..offset+4].try_into().unwrap()) as usize;
        offset += 4;
        let kem_ct = &envelope[offset..offset+kem_ct_len];
        offset += kem_ct_len;

        // Signature
        let sig_len = u32::from_le_bytes(envelope[offset..offset+4].try_into().unwrap()) as usize;
        offset += 4;
        let signature = &envelope[offset..offset+sig_len];
        offset += sig_len;

        // AEAD ciphertext
        let aead_len = u64::from_le_bytes(envelope[offset..offset+8].try_into().unwrap()) as usize;
        offset += 8;
        let aead_ct = &envelope[offset..offset+aead_len];

        // 1. Decapsulate
        let shared_key = decapsulate(recipient, kem_ct)?;
        let key: [u8; 32] = *shared_key;

        // 2. Decrypt
        let plaintext = decrypt(&key, aead_ct)?;

        // 3. Verify signature if sender provided
        if let Some(sender) = sender_public {
            verify(sender, &plaintext, signature)?;
        }

        Ok(plaintext)
    }

    /// Encrypt without signing (anonymous sender).
    pub fn encrypt(plaintext: &[u8], recipient: &PQPublicKey) -> QVResult<Vec<u8>> {
        // Use a throwaway identity for the signature slot
        let anon = PQIdentity::generate()?;
        Self::encrypt_and_sign(plaintext, recipient, &anon)
    }
}
```

### 1.12 `src/lib.rs` — Clean Public API Surface
```rust
//! QuantumVault Core — Post-Quantum Cryptography SDK
//!
//! # Quick Start
//! ```rust
//! use quantumvault_core::{PQIdentity, PQPublicKey, PQFile};
//!
//! // Generate keypairs
//! let alice = PQIdentity::generate().unwrap();
//! let bob   = PQIdentity::generate().unwrap();
//!
//! let alice_pub_bytes = alice.export_public().unwrap();
//! let bob_pub         = PQPublicKey::from_bytes(&bob.export_public().unwrap()).unwrap();
//! let alice_pub       = PQPublicKey::from_bytes(&alice_pub_bytes).unwrap();
//!
//! // Alice encrypts for Bob and signs with her key
//! let envelope = PQFile::encrypt_and_sign(b"secret message", &bob_pub, &alice).unwrap();
//!
//! // Bob decrypts and verifies Alice's signature
//! let plaintext = PQFile::decrypt_and_verify(&envelope, &bob, Some(&alice_pub)).unwrap();
//! assert_eq!(plaintext, b"secret message");
//! ```

pub mod constants;
pub mod error;
pub mod keys;
pub mod kem;
pub mod sign;
pub mod sym;
pub mod kdf;
pub mod file;
pub mod session;

// Flat re-exports for ergonomic API
pub use error::{QVError, QVResult};
pub use keys::identity::{PQIdentity, PQPublicKey};
pub use keys::format::{KeyMeta, KeyType};
pub use file::envelope::PQFile;
pub use session::ratchet::PQSession;
pub use sign::hybrid::{sign, verify};
```

### 1.13 NIST KAT Tests
```rust
// tests/kat_mlkem.rs
// Download NIST KAT vectors from:
// https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
// Place as tests/vectors/mlkem1024_kat.json

#[test]
fn mlkem1024_kat_encapsulate_decapsulate() {
    // Load NIST KAT vectors and verify our encap/decap matches expected shared secrets
    // Agent: implement this by parsing the NIST JSON KAT format
    // Each entry has: ek (encaps key), dk (decaps key), c (ciphertext), K (shared secret)
    todo!("implement NIST KAT verification")
}
```

---

## 2. Phase 2 — Python Bindings (`quantumvault-python`)

> **Goal**: `pip install quantumvault` → 3 lines of Python to encrypt a file. This is the highest-leverage deliverable for developer adoption.

### 2.1 Crate Structure
```
quantumvault-python/
├── Cargo.toml
├── pyproject.toml
├── src/
│   └── lib.rs          # pyo3 bindings
├── quantumvault/
│   ├── __init__.py     # Python wrapper with docstrings
│   └── py.typed        # PEP 561 marker
└── tests/
    └── test_basic.py
```

### 2.2 `quantumvault-python/Cargo.toml`
```toml
[package]
name    = "quantumvault-python"
version = "0.1.0"
edition = "2021"

[lib]
name    = "quantumvault"
crate-type = ["cdylib"]

[dependencies]
quantumvault-core = { path = "../quantumvault-core" }
pyo3 = { version = "0.21", features = ["extension-module"] }

[features]
default     = ["pyo3/auto-initialize"]
extension-module = ["pyo3/extension-module"]
```

### 2.3 `pyproject.toml`
```toml
[build-system]
requires      = ["maturin>=1.5,<2.0"]
build-backend = "maturin"

[project]
name            = "quantumvault"
version         = "0.1.0"
description     = "Post-quantum cryptography SDK — ML-KEM-1024 + ML-DSA-87 + X25519 hybrid"
requires-python = ">=3.8"
license         = { text = "MIT OR Apache-2.0" }
keywords        = ["cryptography", "post-quantum", "ml-kem", "pqc", "security"]
classifiers     = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "Topic :: Security :: Cryptography",
    "Programming Language :: Python :: 3",
    "Programming Language :: Rust",
]

[tool.maturin]
features         = ["pyo3/extension-module"]
python-source    = "quantumvault"
module-name      = "quantumvault._quantumvault"
```

### 2.4 `src/lib.rs` — pyo3 Bindings
```rust
use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;
use quantumvault_core::{PQIdentity, PQPublicKey, PQFile, KeyMeta};

fn qverr(e: quantumvault_core::QVError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

#[pyclass(name = "Identity")]
struct PyIdentity {
    inner: PQIdentity,
}

#[pymethods]
impl PyIdentity {
    /// Generate a new random hybrid keypair.
    #[new]
    #[pyo3(signature = (label=None))]
    fn new(label: Option<String>) -> PyResult<Self> {
        let meta = KeyMeta { label, ..Default::default() };
        let inner = PQIdentity::generate_with_meta(meta).map_err(qverr)?;
        Ok(Self { inner })
    }

    /// Export public key as bytes. Safe to share.
    fn export_public(&self) -> PyResult<Vec<u8>> {
        self.inner.export_public().map_err(qverr)
    }

    /// Export public key as base64 string. Safe to share.
    fn export_public_b64(&self) -> PyResult<String> {
        self.inner.export_public_b64().map_err(qverr)
    }

    /// Export secret key as bytes. Encrypt before storing.
    fn export_secret(&self) -> PyResult<Vec<u8>> {
        self.inner.export_secret().map_err(qverr)
    }

    /// Load identity from previously exported secret key bytes.
    #[staticmethod]
    fn from_secret_bytes(data: &[u8]) -> PyResult<Self> {
        let inner = PQIdentity::from_secret_bytes(data).map_err(qverr)?;
        Ok(Self { inner })
    }
}

#[pyclass(name = "PublicKey")]
struct PyPublicKey {
    inner: PQPublicKey,
}

#[pymethods]
impl PyPublicKey {
    /// Load public key from bytes.
    #[new]
    fn new(data: &[u8]) -> PyResult<Self> {
        let inner = PQPublicKey::from_bytes(data).map_err(qverr)?;
        Ok(Self { inner })
    }

    /// Load public key from base64 string.
    #[staticmethod]
    fn from_b64(s: &str) -> PyResult<Self> {
        let inner = PQPublicKey::from_b64(s).map_err(qverr)?;
        Ok(Self { inner })
    }
}

/// Encrypt bytes for a recipient, optionally signing with sender's identity.
#[pyfunction]
#[pyo3(signature = (data, recipient, sender=None))]
fn encrypt(
    data:      &[u8],
    recipient: &PyPublicKey,
    sender:    Option<&PyIdentity>,
) -> PyResult<Vec<u8>> {
    match sender {
        Some(s) => PQFile::encrypt_and_sign(data, &recipient.inner, &s.inner).map_err(qverr),
        None    => PQFile::encrypt(data, &recipient.inner).map_err(qverr),
    }
}

/// Decrypt an envelope, optionally verifying sender's signature.
#[pyfunction]
#[pyo3(signature = (envelope, recipient, sender_public=None))]
fn decrypt(
    envelope:      &[u8],
    recipient:     &PyIdentity,
    sender_public: Option<&PyPublicKey>,
) -> PyResult<Vec<u8>> {
    PQFile::decrypt_and_verify(
        envelope,
        &recipient.inner,
        sender_public.map(|s| &s.inner),
    ).map_err(qverr)
}

/// Sign bytes with a private key. Returns detached signature bytes.
#[pyfunction]
fn sign(data: &[u8], identity: &PyIdentity) -> PyResult<Vec<u8>> {
    quantumvault_core::sign(&identity.inner, data).map_err(qverr)
}

/// Verify a detached signature. Raises ValueError if invalid.
#[pyfunction]
fn verify(data: &[u8], signature: &[u8], public_key: &PyPublicKey) -> PyResult<()> {
    quantumvault_core::verify(&public_key.inner, data, signature).map_err(qverr)
}

#[pymodule]
fn _quantumvault(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyIdentity>()?;
    m.add_class::<PyPublicKey>()?;
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add("__version__", "0.1.0")?;
    Ok(())
}
```

### 2.5 `quantumvault/__init__.py`
```python
"""
QuantumVault — Post-Quantum Cryptography SDK

Examples
--------
>>> from quantumvault import Identity, PublicKey, encrypt, decrypt

# Generate keypairs
>>> alice = Identity(label="alice")
>>> bob   = Identity(label="bob")

# Encrypt from Alice to Bob (signed)
>>> envelope = encrypt(b"hello world", bob.public_key, sender=alice)

# Bob decrypts and verifies
>>> plaintext = decrypt(envelope, bob, sender_public=alice.public_key)
>>> plaintext
b'hello world'

# File encryption
>>> with open("secret.pdf", "rb") as f: data = f.read()
>>> envelope = encrypt(data, recipient_pub)
>>> with open("secret.pdf.qvf", "wb") as f: f.write(envelope)
"""

from quantumvault._quantumvault import (
    Identity as _Identity,
    PublicKey,
    encrypt,
    decrypt,
    sign,
    verify,
    __version__,
)


class Identity(_Identity):
    """A hybrid post-quantum keypair (X25519 + ML-KEM-1024 + ML-DSA-87).

    Parameters
    ----------
    label : str, optional
        Human-readable name stored in the key metadata.
    """

    @property
    def public_key(self) -> PublicKey:
        """Return the public key for this identity."""
        return PublicKey(self.export_public())

    def save_secret(self, path: str) -> None:
        """Write secret key bytes to file. Encrypt separately before distributing."""
        with open(path, "wb") as f:
            f.write(self.export_secret())

    @classmethod
    def load_secret(cls, path: str) -> "Identity":
        """Load identity from secret key file."""
        with open(path, "rb") as f:
            return cls.from_secret_bytes(f.read())


def encrypt_file(input_path: str, output_path: str, recipient: PublicKey,
                 sender: Identity = None) -> None:
    """Encrypt a file at `input_path` and write envelope to `output_path`."""
    with open(input_path, "rb") as f:
        data = f.read()
    envelope = encrypt(data, recipient, sender)
    with open(output_path, "wb") as f:
        f.write(envelope)


def decrypt_file(input_path: str, output_path: str, recipient: Identity,
                 sender_public: PublicKey = None) -> None:
    """Decrypt a QVF envelope at `input_path` and write plaintext to `output_path`."""
    with open(input_path, "rb") as f:
        envelope = f.read()
    plaintext = decrypt(envelope, recipient, sender_public)
    with open(output_path, "wb") as f:
        f.write(plaintext)


__all__ = [
    "Identity", "PublicKey",
    "encrypt", "decrypt", "sign", "verify",
    "encrypt_file", "decrypt_file",
    "__version__",
]
```

### 2.6 `tests/test_basic.py`
```python
import pytest
from quantumvault import Identity, PublicKey, encrypt, decrypt, sign, verify

def test_roundtrip():
    alice = Identity(label="alice")
    bob   = Identity(label="bob")
    msg   = b"hello post-quantum world"

    envelope  = encrypt(msg, bob.public_key, sender=alice)
    plaintext = decrypt(envelope, bob, sender_public=alice.public_key)
    assert plaintext == msg

def test_anonymous_encrypt():
    bob      = Identity()
    envelope = encrypt(b"anonymous", bob.public_key)
    result   = decrypt(envelope, bob)
    assert result == b"anonymous"

def test_sign_verify():
    alice = Identity()
    msg   = b"signed message"
    sig   = sign(msg, alice)
    verify(msg, sig, alice.public_key)  # should not raise

def test_verify_fails_on_tampered_message():
    alice = Identity()
    sig   = sign(b"original", alice)
    with pytest.raises(ValueError):
        verify(b"tampered", sig, alice.public_key)

def test_key_export_import():
    alice       = Identity(label="persistence test")
    secret_bytes = alice.export_secret()
    alice2      = Identity.from_secret_bytes(secret_bytes)
    assert alice.export_public() == alice2.export_public()

def test_wrong_recipient_fails():
    alice = Identity()
    bob   = Identity()
    carol = Identity()
    envelope = encrypt(b"for bob only", bob.public_key)
    with pytest.raises(ValueError):
        decrypt(envelope, carol)
```

### 2.7 Build & Publish Commands
```bash
cd quantumvault-python

# Development install
maturin develop

# Run tests
pytest tests/ -v

# Build wheel for distribution
maturin build --release

# Publish to PyPI
maturin publish
```

---

## 3. Phase 3 — WASM Bindings (`quantumvault-wasm`)

> **Goal**: `import { Identity, encrypt, decrypt } from '@quantumvault/wasm'` in browser or Node.js.

### 3.1 `quantumvault-wasm/Cargo.toml`
```toml
[package]
name    = "quantumvault-wasm"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
quantumvault-core = { path = "../quantumvault-core" }
wasm-bindgen      = "0.2"
js-sys            = "0.3"
serde-wasm-bindgen = "0.6"
getrandom         = { version = "0.2", features = ["js"] }
console_error_panic_hook = "0.1"

[features]
default = []
```

### 3.2 `src/lib.rs`
```rust
use wasm_bindgen::prelude::*;
use quantumvault_core::{PQIdentity, PQPublicKey, PQFile};

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

fn to_js_err(e: quantumvault_core::QVError) -> JsValue {
    JsValue::from_str(&e.to_string())
}

#[wasm_bindgen]
pub struct Identity {
    inner: PQIdentity,
}

#[wasm_bindgen]
impl Identity {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Identity, JsValue> {
        PQIdentity::generate()
            .map(|inner| Identity { inner })
            .map_err(to_js_err)
    }

    pub fn export_public(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.export_public().map_err(to_js_err)
    }

    pub fn export_public_b64(&self) -> Result<String, JsValue> {
        self.inner.export_public_b64().map_err(to_js_err)
    }

    pub fn export_secret(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.export_secret().map_err(to_js_err)
    }

    pub fn from_secret_bytes(data: &[u8]) -> Result<Identity, JsValue> {
        PQIdentity::from_secret_bytes(data)
            .map(|inner| Identity { inner })
            .map_err(to_js_err)
    }
}

#[wasm_bindgen]
pub struct PublicKey {
    inner: PQPublicKey,
}

#[wasm_bindgen]
impl PublicKey {
    #[wasm_bindgen(constructor)]
    pub fn new(data: &[u8]) -> Result<PublicKey, JsValue> {
        PQPublicKey::from_bytes(data)
            .map(|inner| PublicKey { inner })
            .map_err(to_js_err)
    }

    pub fn from_b64(s: &str) -> Result<PublicKey, JsValue> {
        PQPublicKey::from_b64(s)
            .map(|inner| PublicKey { inner })
            .map_err(to_js_err)
    }
}

#[wasm_bindgen]
pub fn encrypt(data: &[u8], recipient: &PublicKey) -> Result<Vec<u8>, JsValue> {
    PQFile::encrypt(data, &recipient.inner).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn encrypt_signed(data: &[u8], recipient: &PublicKey, sender: &Identity) -> Result<Vec<u8>, JsValue> {
    PQFile::encrypt_and_sign(data, &recipient.inner, &sender.inner).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn decrypt(envelope: &[u8], recipient: &Identity) -> Result<Vec<u8>, JsValue> {
    PQFile::decrypt_and_verify(envelope, &recipient.inner, None).map_err(to_js_err)
}
```

### 3.3 Build WASM
```bash
cd quantumvault-wasm
wasm-pack build --target web --out-dir pkg
# For Node.js:
wasm-pack build --target nodejs --out-dir pkg-node
```

---

## 4. Phase 4 — C FFI (`quantumvault-ffi`)

> **Goal**: A stable C ABI with an auto-generated header. Enables binding to Go, Java (JNI), Swift, Ruby, etc.

### 4.1 `src/lib.rs`
```rust
use std::ffi::{c_char, CStr, CString};
use quantumvault_core::{PQIdentity, PQPublicKey, PQFile};

/// Opaque handle types
pub struct QVIdentityHandle(PQIdentity);
pub struct QVPublicKeyHandle(PQPublicKey);

/// Result codes
#[repr(C)]
pub enum QVStatus {
    Ok          = 0,
    Error       = 1,
    InvalidArg  = 2,
    BufferSmall = 3,
}

/// Generate a new identity. Caller owns the returned handle.
/// Free with qv_identity_free().
#[no_mangle]
pub extern "C" fn qv_identity_generate() -> *mut QVIdentityHandle {
    match PQIdentity::generate() {
        Ok(id) => Box::into_raw(Box::new(QVIdentityHandle(id))),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn qv_identity_free(handle: *mut QVIdentityHandle) {
    if !handle.is_null() {
        unsafe { drop(Box::from_raw(handle)); }
    }
}

/// Export public key bytes into caller-provided buffer.
/// If buf is NULL or buf_len is too small, writes required length to out_len and returns BufferSmall.
#[no_mangle]
pub extern "C" fn qv_identity_export_public(
    handle:  *const QVIdentityHandle,
    buf:     *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> QVStatus {
    if handle.is_null() || out_len.is_null() { return QVStatus::InvalidArg; }
    let id = unsafe { &(*handle).0 };
    match id.export_public() {
        Err(_) => QVStatus::Error,
        Ok(bytes) => {
            unsafe { *out_len = bytes.len(); }
            if buf.is_null() || buf_len < bytes.len() {
                return QVStatus::BufferSmall;
            }
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len()); }
            QVStatus::Ok
        }
    }
}

// Agent: implement remaining FFI functions following the same pattern:
// qv_identity_export_secret, qv_identity_from_secret_bytes,
// qv_public_key_from_bytes, qv_public_key_free,
// qv_encrypt, qv_decrypt, qv_sign, qv_verify
// Each function follows: pointer args → output to caller buffer → return QVStatus
```

### 4.2 Generate C Header
```bash
cd quantumvault-ffi

cat > cbindgen.toml << 'EOF'
language = "C"
header   = "/* QuantumVault C API — auto-generated. Do not edit. */"
include_guard = "QUANTUMVAULT_H"
EOF

cbindgen --config cbindgen.toml --crate quantumvault-ffi --output include/quantumvault.h
```

---

## 5. Phase 5 — CLI (`quantumvault-cli`)

### 5.1 Commands to Implement
```
qv keygen [--label NAME] [--out DIR]
    Generate new keypair, write public.qvk and secret.qvk to DIR

qv encrypt FILE [--to PUBKEY_FILE] [--from SECRET_KEY_FILE] [--out OUTPUT]
    Encrypt FILE producing FILE.qvf

qv decrypt FILE.qvf [--with SECRET_KEY_FILE] [--verify PUBKEY_FILE] [--out OUTPUT]
    Decrypt envelope

qv sign FILE [--with SECRET_KEY_FILE] [--out FILE.qvs]
    Produce detached signature

qv verify FILE [--sig FILE.qvs] [--with PUBKEY_FILE]
    Verify detached signature

qv inspect FILE
    Show key metadata, creation date, type from any .qvk or .qvf file
```

### 5.2 `quantumvault-cli/Cargo.toml`
```toml
[package]
name    = "qv"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "qv"
path = "src/main.rs"

[dependencies]
quantumvault-core = { path = "../quantumvault-core" }
clap  = { version = "4", features = ["derive"] }
anyhow = { workspace = true }
```

---

## 6. Testing Requirements

> The agent must achieve all of the following before any phase is considered complete.

### 6.1 Unit Tests (run with `cargo test`)
- [ ] All NIST KAT vectors for ML-KEM-1024 pass
- [ ] All NIST KAT vectors for ML-DSA-87 pass
- [ ] Encrypt → decrypt roundtrip (same key)
- [ ] Cross-key decryption fails with `DecryptionFailed`
- [ ] Tampered ciphertext fails with `DecryptionFailed`
- [ ] Tampered signature fails with `VerificationFailed`
- [ ] Key export → import roundtrip produces identical public key bytes
- [ ] QVKey format: magic mismatch returns `InvalidMagic`
- [ ] QVKey format: checksum corruption returns `InvalidKeyFormat`
- [ ] File too large returns `FileTooLarge`

### 6.2 Python Tests (run with `pytest`)
- [ ] All roundtrip tests in `test_basic.py` pass
- [ ] `Identity.save_secret` → `Identity.load_secret` roundtrip
- [ ] `encrypt_file` / `decrypt_file` on a 10MB binary file
- [ ] Type errors on wrong argument types raise `TypeError`

### 6.3 Benchmarks (run with `cargo criterion`)
Target performance on modern hardware (M2/Ryzen 5):
- Key generation:   < 50 ms
- Encapsulate:      < 5 ms
- Decapsulate:      < 5 ms
- Encrypt 1MB file: < 20 ms
- Decrypt 1MB file: < 20 ms
- Sign:             < 50 ms
- Verify:           < 10 ms

### 6.4 Security Checks
```bash
# Audit dependencies for known vulnerabilities
cargo audit

# Deny policy (add deny.toml at workspace root)
cargo deny check

# Code coverage (target: >85%)
cargo tarpaulin --out Html
```

---

## 7. `deny.toml` — Dependency Policy
```toml
[advisories]
vulnerability = "deny"
unmaintained  = "warn"
yanked        = "deny"

[licenses]
allow = ["MIT", "Apache-2.0", "ISC", "BSD-2-Clause", "BSD-3-Clause"]
deny  = ["GPL-2.0", "GPL-3.0", "AGPL-3.0"]

[bans]
multiple-versions = "warn"
```

---

## 8. Documentation Site

> **Stack**: Docusaurus 3 + mdx. Hosted on GitHub Pages.

### 8.1 File Structure
```
docs-site/
├── docs/
│   ├── index.md              # "Encrypt a file in 3 lines" hero
│   ├── quickstart.md         # Python 5-minute guide
│   ├── concepts/
│   │   ├── hybrid-kem.md     # Why X25519 + ML-KEM, not just ML-KEM
│   │   ├── key-format.md     # QVKey v1 spec (human-readable)
│   │   └── threat-model.md   # What QuantumVault protects against
│   ├── python-api.md         # Full Python API reference
│   ├── rust-api.md           # Rust crate docs link
│   ├── wasm-api.md           # Browser/Node.js usage
│   └── c-api.md              # C header reference
├── docusaurus.config.js
└── package.json
```

### 8.2 Hero Demo (first thing on docs homepage)
```python
# 3 lines to encrypt a file
from quantumvault import Identity, encrypt, decrypt

alice = Identity()
bob   = Identity()
envelope = encrypt(b"Hello post-quantum world!", bob.public_key, sender=alice)
plaintext = decrypt(envelope, bob, sender_public=alice.public_key)
# b"Hello post-quantum world!"
```

---

## 9. GitHub Repository Setup

### 9.1 `.github/workflows/ci.yml`
```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  rust-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --workspace
      - run: cargo audit
      - run: cargo deny check

  python-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - run: pip install maturin pytest
      - run: cd quantumvault-python && maturin develop && pytest tests/ -v

  wasm-build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { targets: wasm32-unknown-unknown }
      - run: cargo install wasm-pack
      - run: cd quantumvault-wasm && wasm-pack build --target web
```

### 9.2 `README.md` Opening Section
```markdown
# QuantumVault SDK

**The libsodium of post-quantum cryptography.**

Hybrid X25519 + ML-KEM-1024 key encapsulation, ML-DSA-87 signatures,
ChaCha20-Poly1305 encryption — in one opinionated SDK with zero crypto knowledge required.

```python
pip install quantumvault
```

```python
from quantumvault import Identity, encrypt, decrypt

alice    = Identity()
bob      = Identity()
envelope = encrypt(b"secret", bob.public_key, sender=alice)
message  = decrypt(envelope, bob, sender_public=alice.public_key)
```

**Standards**: NIST FIPS 203 (ML-KEM) · NIST FIPS 204 (ML-DSA) · RFC 7748 (X25519)
```

---

## 10. Agent Execution Order

The agent must follow this exact sequence. Do not proceed to the next step until the current step's success criteria are met.

```
Step 01  Init workspace Cargo.toml and git repo
Step 02  Create quantumvault-core/Cargo.toml
Step 03  Implement constants.rs
Step 04  Implement error.rs
Step 05  Implement kdf/hkdf.rs
Step 06  Implement sym/aead.rs
Step 07  Implement keys/format.rs  (add blake3 dependency)
Step 08  Implement keys/identity.rs
Step 09  Implement kem/hybrid.rs
Step 10  Implement sign/hybrid.rs
Step 11  Implement file/envelope.rs
Step 12  Implement lib.rs
Step 13  cargo build -p quantumvault-core  [MUST PASS]
Step 14  Write tests/roundtrip.rs and run cargo test  [MUST PASS]
Step 15  Implement quantumvault-python bindings
Step 16  maturin develop && pytest tests/  [MUST PASS]
Step 17  Implement quantumvault-wasm
Step 18  wasm-pack build --target web  [MUST PASS]
Step 19  Implement quantumvault-ffi + generate C header
Step 20  Implement quantumvault-cli
Step 21  cargo test --workspace  [ALL TESTS MUST PASS]
Step 22  cargo audit && cargo deny check  [MUST PASS]
Step 23  Write documentation site skeleton
Step 24  Set up GitHub Actions CI
Step 25  Tag v0.1.0 and push
```

---

## 11. Known Pitfalls & Agent Notes

1. **ML-KEM secret key embeds the public key** in the final 1568 bytes of the 3168-byte secret key (NIST FIPS 203 §2.4). When reconstructing a public key from a secret key, read from offset `[2 * MLKEM1024_PUBLIC_KEY_SIZE - MLKEM1024_SECRET_KEY_SIZE]` or just store both separately (preferred).

2. **pqcrypto-mlkem crate naming**: the crate is `pqcrypto-mlkem` (hyphen), the module is `pqcrypto_mlkem::mlkem1024` (underscore, then `mlkem1024` not `kyber1024`). Do not confuse with the older `pqcrypto-kyber` crate.

3. **WASM and getrandom**: `getrandom` requires the `js` feature to use `crypto.getRandomValues` in browsers. Without this, `OsRng` panics in WASM. Already set in workspace dependencies.

4. **Zeroize and pqcrypto types**: `pqcrypto` types do not implement `Zeroize`. The secret key bytes live in the struct fields and are dropped normally. To ensure they are overwritten on drop, extract the bytes as a `Zeroizing<Vec<u8>>` during operations and drop immediately after use.

5. **Nonce reuse is catastrophic**: `chacha20poly1305` uses random 96-bit nonces per call. Our `encrypt` in `sym/aead.rs` generates a fresh nonce each call. Never cache or reuse nonce values.

6. **Cross-platform CI**: WASM builds require `wasm32-unknown-unknown` target. `wasm-pack` must be installed separately. Add it to CI as shown in step 9.1.

7. **cbindgen version**: pin `cbindgen` to `0.26` in the CI to avoid generated header format changes breaking downstream consumers.

8. **PyPI package name**: `quantumvault` may already be taken on PyPI. Check before publishing. If taken, use `quantumvault-sdk`.
```
