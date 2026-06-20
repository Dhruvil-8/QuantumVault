//! QuantumVault Core Cryptography Library
//!
//! Exposes the primary cryptographic primitives, key verification,
//! and hybrid file encryption stream capabilities.

pub mod errors;
pub mod crypto;
pub mod vault;

// Re-export main types
pub use crypto::identity::Identity;
pub use crypto::public::{RecipientPublic, SenderPublic};
pub use vault::{encrypt_file, decrypt_file};
pub use errors::VaultError;
