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
pub mod util;

// Flat re-exports for ergonomic API
pub use error::{QVError, QVResult};
pub use keys::identity::{PQIdentity, PQPublicKey};
pub use keys::format::{KeyMeta, KeyType};
pub use file::envelope::PQFile;
pub use session::ratchet::PQSession;
pub use sign::hybrid::{sign, verify};
pub use util::write_secure_file;
