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
