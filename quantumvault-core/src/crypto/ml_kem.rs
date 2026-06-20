//! ML-KEM-1024 Module (NIST FIPS 203)
//!
//! This module provides quantum-resistant key encapsulation using the
//! Module-Lattice-Based Key-Encapsulation Mechanism standardized by NIST.

use fips203::ml_kem_1024;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};

/// Size constants for ML-KEM-1024
pub const ENCAPSULATION_KEY_SIZE: usize = 1568;
pub const DECAPSULATION_KEY_SIZE: usize = 3168;
pub const CIPHERTEXT_SIZE: usize = 1568;
pub const SHARED_SECRET_SIZE: usize = 32;

/// ML-KEM-1024 Encapsulation Key (public key for encryption)
#[derive(Clone)]
pub struct MlKemEncapsulationKey(pub ml_kem_1024::EncapsKey);

/// ML-KEM-1024 Decapsulation Key (private key for decryption)
pub struct MlKemDecapsulationKey(pub ml_kem_1024::DecapsKey);

/// ML-KEM-1024 Ciphertext
#[derive(Clone)]
pub struct MlKemCiphertext(pub ml_kem_1024::CipherText);

use zeroize::Zeroize;

/// ML-KEM-1024 Shared Secret (32 bytes)
pub struct MlKemSharedSecret(pub [u8; SHARED_SECRET_SIZE]);

impl Zeroize for MlKemSharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for MlKemSharedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl MlKemEncapsulationKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != ENCAPSULATION_KEY_SIZE {
            return Err("Invalid encapsulation key size");
        }
        let arr: [u8; ENCAPSULATION_KEY_SIZE] = bytes.try_into()
            .map_err(|_| "Invalid encapsulation key size")?;
        let ek = ml_kem_1024::EncapsKey::try_from_bytes(arr)
            .map_err(|_| "Invalid encapsulation key")?;
        Ok(Self(ek))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> [u8; ENCAPSULATION_KEY_SIZE] {
        self.0.clone().into_bytes()
    }
}

impl MlKemDecapsulationKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != DECAPSULATION_KEY_SIZE {
            return Err("Invalid decapsulation key size");
        }
        let arr: [u8; DECAPSULATION_KEY_SIZE] = bytes.try_into()
            .map_err(|_| "Invalid decapsulation key size")?;
        let dk = ml_kem_1024::DecapsKey::try_from_bytes(arr)
            .map_err(|_| "Invalid decapsulation key")?;
        Ok(Self(dk))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> [u8; DECAPSULATION_KEY_SIZE] {
        self.0.clone().into_bytes()
    }
}

impl MlKemCiphertext {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != CIPHERTEXT_SIZE {
            return Err("Invalid ciphertext size");
        }
        let arr: [u8; CIPHERTEXT_SIZE] = bytes.try_into()
            .map_err(|_| "Invalid ciphertext size")?;
        let ct = ml_kem_1024::CipherText::try_from_bytes(arr)
            .map_err(|_| "Invalid ciphertext")?;
        Ok(Self(ct))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> [u8; CIPHERTEXT_SIZE] {
        self.0.clone().into_bytes()
    }
}

impl MlKemSharedSecret {
    /// Get raw bytes (32 bytes)
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_SIZE] {
        &self.0
    }
}

/// Generate a new ML-KEM-1024 keypair
pub fn generate() -> (MlKemEncapsulationKey, MlKemDecapsulationKey) {
    let (ek, dk) = ml_kem_1024::KG::try_keygen().expect("ML-KEM keygen failed");
    (MlKemEncapsulationKey(ek), MlKemDecapsulationKey(dk))
}

/// Encapsulate a shared secret for the given encapsulation key
/// Returns (shared_secret, ciphertext)
pub fn encapsulate(ek: &MlKemEncapsulationKey) -> (MlKemSharedSecret, MlKemCiphertext) {
    let (ssk_bytes, ct) = ek.0.try_encaps().expect("ML-KEM encapsulation failed");
    (MlKemSharedSecret(ssk_bytes.into_bytes()), MlKemCiphertext(ct))
}

/// Decapsulate a ciphertext using the decapsulation key
pub fn decapsulate(ct: &MlKemCiphertext, dk: &MlKemDecapsulationKey) -> MlKemSharedSecret {
    let ssk_bytes = dk.0.try_decaps(&ct.0).expect("ML-KEM decapsulation failed");
    MlKemSharedSecret(ssk_bytes.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_encaps_decaps() {
        let (ek, dk) = generate();
        let (ss1, ct) = encapsulate(&ek);
        let ss2 = decapsulate(&ct, &dk);
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_key_serialization() {
        let (ek, dk) = generate();
        
        // Round-trip encapsulation key
        let ek_bytes = ek.as_bytes();
        let ek2 = MlKemEncapsulationKey::from_bytes(&ek_bytes).unwrap();
        assert_eq!(ek.as_bytes(), ek2.as_bytes());
        
        // Round-trip decapsulation key
        let dk_bytes = dk.as_bytes();
        let dk2 = MlKemDecapsulationKey::from_bytes(&dk_bytes).unwrap();
        assert_eq!(dk.as_bytes(), dk2.as_bytes());
    }

    #[test]
    fn test_ciphertext_serialization() {
        let (ek, dk) = generate();
        let (_, ct) = encapsulate(&ek);
        
        // Round-trip ciphertext
        let ct_bytes = ct.as_bytes();
        let ct2 = MlKemCiphertext::from_bytes(&ct_bytes).unwrap();
        
        // Decapsulate with deserialized ciphertext should work
        let ss = decapsulate(&ct2, &dk);
        assert_eq!(ss.as_bytes().len(), SHARED_SECRET_SIZE);
    }
}
