//! Public Key Structures
//!
//! These structures hold only the public portions of keys,
//! used for encrypting to recipients and verifying senders.

use std::path::Path;
use std::fs;
use crate::errors::VaultError;
use crate::crypto::identity::Identity;

/// Public keys needed to encrypt a message to a recipient
#[derive(Clone)]
pub struct RecipientPublic {
    /// X25519 public key (32 bytes)
    pub x25519_pub: Vec<u8>,
    /// ML-KEM-1024 encapsulation key
    pub ml_kem_pub: Vec<u8>,
}

/// Public keys needed to verify a sender's signature
#[derive(Clone)]
pub struct SenderPublic {
    /// ML-DSA-65 public key
    pub ml_dsa_pub: Vec<u8>,
}

impl RecipientPublic {
    /// Load recipient's public keys from disk
    pub fn load(base: impl AsRef<Path>) -> Result<Self, VaultError> {
        let enc = base.as_ref().join("encryption");
        let x25519_pub = fs::read(enc.join("x25519.pub")).map_err(VaultError::Io)?;
        let ml_kem_pub = fs::read(enc.join("ml_kem.pub")).map_err(VaultError::Io)?;
        Ok(Self {
            x25519_pub,
            ml_kem_pub,
        })
    }

    /// Create from raw bytes
    pub fn from_bytes(x25519: &[u8], ml_kem: &[u8]) -> Self {
        Self {
            x25519_pub: x25519.to_vec(),
            ml_kem_pub: ml_kem.to_vec(),
        }
    }
}

impl SenderPublic {
    /// Load sender's public signing key from disk
    pub fn load(base: impl AsRef<Path>) -> Result<Self, VaultError> {
        let sig = base.as_ref().join("signing");
        let ml_dsa_pub = fs::read(sig.join("ml_dsa.pub")).map_err(VaultError::Io)?;
        Ok(Self {
            ml_dsa_pub,
        })
    }

    /// Create from raw bytes
    pub fn from_bytes(ml_dsa: &[u8]) -> Self {
        Self {
            ml_dsa_pub: ml_dsa.to_vec(),
        }
    }
}

impl Identity {
    /// Extract the public encryption keys for this identity
    pub fn recipient_public(&self) -> RecipientPublic {
        RecipientPublic {
            x25519_pub: self.x25519.public.as_bytes().to_vec(),
            ml_kem_pub: self.ml_kem_ek.as_bytes().to_vec(),
        }
    }

    /// Extract the public signing key for this identity
    pub fn sender_public(&self) -> SenderPublic {
        SenderPublic {
            ml_dsa_pub: self.ml_dsa_pk.as_bytes().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ml_kem::ENCAPSULATION_KEY_SIZE;
    use crate::crypto::ml_dsa::PUBLIC_KEY_SIZE;

    #[test]
    fn test_recipient_public_from_identity() {
        let identity = Identity::generate().unwrap();
        let recipient = identity.recipient_public();
        
        assert_eq!(recipient.x25519_pub.len(), 32);
        assert_eq!(recipient.ml_kem_pub.len(), ENCAPSULATION_KEY_SIZE);
    }

    #[test]
    fn test_sender_public_from_identity() {
        let identity = Identity::generate().unwrap();
        let sender = identity.sender_public();
        
        assert_eq!(sender.ml_dsa_pub.len(), PUBLIC_KEY_SIZE);
    }
}

