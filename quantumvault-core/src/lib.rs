//! QuantumVault Core Cryptography Library
//!
//! Exposes the primary cryptographic primitives, key verification,
//! and hybrid file encryption stream capabilities.

pub mod crypto;
pub mod errors;
pub mod vault;

// Re-export main types
pub use crypto::identity::Identity;
pub use crypto::public::{RecipientPublic, SenderPublic};
pub use errors::VaultError;
pub use vault::{decrypt_file, encrypt_file};
