//! ML-KEM-1024 Module (NIST FIPS 203)
//!
//! This module provides quantum-resistant key encapsulation using the
//! Module-Lattice-Based Key-Encapsulation Mechanism standardized by NIST.

use fips203::ml_kem_1024;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};

use crate::errors::VaultError;

/// Size constants for ML-KEM-1024
pub const ENCAPSULATION_KEY_SIZE: usize = 1568;
pub const DECAPSULATION_KEY_SIZE: usize = 3168;
pub const CIPHERTEXT_SIZE: usize = 1568;
pub const SHARED_SECRET_SIZE: usize = 32;

/// ML-KEM-1024 Encapsulation Key (public key for encryption)
#[derive(Clone)]
pub struct MlKemEncapsulationKey(pub(crate) ml_kem_1024::EncapsKey);

/// ML-KEM-1024 Decapsulation Key (private key for decryption)
pub struct MlKemDecapsulationKey(pub(crate) ml_kem_1024::DecapsKey);

/// ML-KEM-1024 Ciphertext
#[derive(Clone)]
pub struct MlKemCiphertext(pub(crate) ml_kem_1024::CipherText);

use zeroize::Zeroize;

/// ML-KEM-1024 Shared Secret (32 bytes)
pub struct MlKemSharedSecret(pub(crate) [u8; SHARED_SECRET_SIZE]);

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

impl Drop for MlKemDecapsulationKey {
    fn drop(&mut self) {
        // Zeroize the decapsulation key memory by overwriting with zeros.
        // The inner type is opaque, so we use unsafe pointer write.
        // SAFETY: We are writing zeros over a validly-allocated, sized region
        // that we own exclusively (we have &mut self).
        unsafe {
            std::ptr::write_bytes(
                &mut self.0 as *mut _ as *mut u8,
                0,
                std::mem::size_of::<ml_kem_1024::DecapsKey>(),
            );
        }
        // Prevent the compiler from eliding the zero-write as a dead store.
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl MlKemEncapsulationKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != ENCAPSULATION_KEY_SIZE {
            return Err("Invalid encapsulation key size");
        }
        let arr: [u8; ENCAPSULATION_KEY_SIZE] = bytes
            .try_into()
            .map_err(|_| "Invalid encapsulation key size")?;
        let ek =
            ml_kem_1024::EncapsKey::try_from_bytes(arr).map_err(|_| "Invalid encapsulation key")?;
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
        let arr: [u8; DECAPSULATION_KEY_SIZE] = bytes
            .try_into()
            .map_err(|_| "Invalid decapsulation key size")?;
        let dk =
            ml_kem_1024::DecapsKey::try_from_bytes(arr).map_err(|_| "Invalid decapsulation key")?;
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
        let arr: [u8; CIPHERTEXT_SIZE] = bytes.try_into().map_err(|_| "Invalid ciphertext size")?;
        let ct = ml_kem_1024::CipherText::try_from_bytes(arr).map_err(|_| "Invalid ciphertext")?;
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
pub fn generate() -> Result<(MlKemEncapsulationKey, MlKemDecapsulationKey), VaultError> {
    let (ek, dk) = ml_kem_1024::KG::try_keygen().map_err(|_| VaultError::KeygenFailed)?;
    Ok((MlKemEncapsulationKey(ek), MlKemDecapsulationKey(dk)))
}

/// Encapsulate a shared secret for the given encapsulation key
/// Returns (shared_secret, ciphertext)
pub fn encapsulate(
    ek: &MlKemEncapsulationKey,
) -> Result<(MlKemSharedSecret, MlKemCiphertext), VaultError> {
    let (ssk_bytes, ct) = ek.0.try_encaps().map_err(|_| VaultError::CryptoError)?;
    Ok((
        MlKemSharedSecret(ssk_bytes.into_bytes()),
        MlKemCiphertext(ct),
    ))
}

/// Decapsulate a ciphertext using the decapsulation key
pub fn decapsulate(
    ct: &MlKemCiphertext,
    dk: &MlKemDecapsulationKey,
) -> Result<MlKemSharedSecret, VaultError> {
    let ssk_bytes =
        dk.0.try_decaps(&ct.0)
            .map_err(|_| VaultError::CryptoError)?;
    Ok(MlKemSharedSecret(ssk_bytes.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_encaps_decaps() {
        let (ek, dk) = generate().unwrap();
        let (ss1, ct) = encapsulate(&ek).unwrap();
        let ss2 = decapsulate(&ct, &dk).unwrap();
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn test_wrong_decapsulation_key() {
        let (ek, _dk) = generate().unwrap();
        let (_ek2, dk2) = generate().unwrap();

        let (ss_sender, ct) = encapsulate(&ek).unwrap();
        // Decapsulate with wrong key should produce a different shared secret
        // (ML-KEM implicit rejection returns a pseudo-random value, not an error)
        let ss_wrong = decapsulate(&ct, &dk2).unwrap();
        assert_ne!(
            ss_sender.as_bytes(),
            ss_wrong.as_bytes(),
            "Wrong DK must produce different shared secret"
        );
    }

    #[test]
    fn test_encapsulation_nondeterminism() {
        let (ek, dk) = generate().unwrap();

        let (ss1, ct1) = encapsulate(&ek).unwrap();
        let (ss2, ct2) = encapsulate(&ek).unwrap();

        // Each encapsulation should produce different ciphertext and shared secret
        assert_ne!(ct1.as_bytes(), ct2.as_bytes());
        assert_ne!(ss1.as_bytes(), ss2.as_bytes());

        // But both should decapsulate correctly
        let dss1 = decapsulate(&ct1, &dk).unwrap();
        let dss2 = decapsulate(&ct2, &dk).unwrap();
        assert_eq!(ss1.as_bytes(), dss1.as_bytes());
        assert_eq!(ss2.as_bytes(), dss2.as_bytes());
    }

    #[test]
    fn test_key_serialization() {
        let (ek, dk) = generate().unwrap();

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
        let (ek, dk) = generate().unwrap();
        let (_, ct) = encapsulate(&ek).unwrap();

        // Round-trip ciphertext
        let ct_bytes = ct.as_bytes();
        let ct2 = MlKemCiphertext::from_bytes(&ct_bytes).unwrap();

        // Decapsulate with deserialized ciphertext should work
        let ss = decapsulate(&ct2, &dk).unwrap();
        assert_eq!(ss.as_bytes().len(), SHARED_SECRET_SIZE);
    }

    #[test]
    fn test_invalid_key_sizes_rejected() {
        // Too short
        assert!(MlKemEncapsulationKey::from_bytes(&[0u8; 10]).is_err());
        assert!(MlKemDecapsulationKey::from_bytes(&[0u8; 10]).is_err());
        assert!(MlKemCiphertext::from_bytes(&[0u8; 10]).is_err());

        // Too long
        assert!(MlKemEncapsulationKey::from_bytes(&vec![0u8; ENCAPSULATION_KEY_SIZE + 1]).is_err());
        assert!(MlKemDecapsulationKey::from_bytes(&vec![0u8; DECAPSULATION_KEY_SIZE + 1]).is_err());
        assert!(MlKemCiphertext::from_bytes(&vec![0u8; CIPHERTEXT_SIZE + 1]).is_err());

        // Empty
        assert!(MlKemEncapsulationKey::from_bytes(&[]).is_err());
        assert!(MlKemDecapsulationKey::from_bytes(&[]).is_err());
        assert!(MlKemCiphertext::from_bytes(&[]).is_err());
    }

    #[test]
    fn test_shared_secret_is_32_bytes() {
        let (ek, dk) = generate().unwrap();
        let (ss, ct) = encapsulate(&ek).unwrap();
        let ss2 = decapsulate(&ct, &dk).unwrap();

        assert_eq!(ss.as_bytes().len(), 32);
        assert_eq!(ss2.as_bytes().len(), 32);
    }
}
