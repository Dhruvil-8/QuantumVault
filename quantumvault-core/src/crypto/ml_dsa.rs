//! ML-DSA-85 Module (NIST FIPS 204)
//!
//! This module provides quantum-resistant digital signatures using the
//! Module-Lattice-Based Digital Signature Algorithm standardized by NIST.

use fips204::ml_dsa_87;
use fips204::traits::{SerDes, Signer, Verifier};

use crate::errors::VaultError;

/// Size constants for ML-DSA-85
pub const PUBLIC_KEY_SIZE: usize = 2592;
pub const PRIVATE_KEY_SIZE: usize = 4896;
pub const SIGNATURE_SIZE: usize = 4627;

/// ML-DSA-85 Public Key (for verification)
#[derive(Clone)]
pub struct MlDsaPublicKey(pub(crate) ml_dsa_87::PublicKey);

/// ML-DSA-85 Private Key (for signing)
pub struct MlDsaPrivateKey(pub(crate) ml_dsa_87::PrivateKey);

/// ML-DSA-85 Signature
#[derive(Clone)]
pub struct MlDsaSignature(pub(crate) [u8; SIGNATURE_SIZE]);

impl Drop for MlDsaPrivateKey {
    fn drop(&mut self) {
        // Zeroize the private key memory by overwriting with zeros.
        // The inner type is opaque, so we use unsafe pointer write.
        // SAFETY: We are writing zeros over a validly-allocated, sized region
        // that we own exclusively (we have &mut self).
        unsafe {
            std::ptr::write_bytes(
                &mut self.0 as *mut _ as *mut u8,
                0,
                std::mem::size_of::<ml_dsa_87::PrivateKey>(),
            );
        }
        // Prevent the compiler from eliding the zero-write as a dead store.
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl MlDsaPublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err("Invalid public key size");
        }
        let arr: [u8; PUBLIC_KEY_SIZE] = bytes.try_into().map_err(|_| "Invalid public key size")?;
        let pk = ml_dsa_87::PublicKey::try_from_bytes(arr).map_err(|_| "Invalid public key")?;
        Ok(Self(pk))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.0.clone().into_bytes()
    }
}

impl MlDsaPrivateKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != PRIVATE_KEY_SIZE {
            return Err("Invalid private key size");
        }
        let arr: [u8; PRIVATE_KEY_SIZE] =
            bytes.try_into().map_err(|_| "Invalid private key size")?;
        let sk = ml_dsa_87::PrivateKey::try_from_bytes(arr).map_err(|_| "Invalid private key")?;
        Ok(Self(sk))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> [u8; PRIVATE_KEY_SIZE] {
        self.0.clone().into_bytes()
    }
}

impl MlDsaSignature {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err("Invalid signature size");
        }
        let arr: [u8; SIGNATURE_SIZE] = bytes.try_into().map_err(|_| "Invalid signature size")?;
        Ok(Self(arr))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }
}

/// Generate a new ML-DSA-85 keypair
pub fn generate() -> Result<(MlDsaPublicKey, MlDsaPrivateKey), VaultError> {
    let (pk, sk) = ml_dsa_87::try_keygen().map_err(|_| VaultError::KeygenFailed)?;
    Ok((MlDsaPublicKey(pk), MlDsaPrivateKey(sk)))
}

/// Sign a message using the private key
pub fn sign(message: &[u8], sk: &MlDsaPrivateKey) -> Result<MlDsaSignature, VaultError> {
    // Empty context per NIST spec for basic signatures
    let sig_bytes =
        sk.0.try_sign(message, &[])
            .map_err(|_| VaultError::SigningFailed)?;
    Ok(MlDsaSignature(sig_bytes))
}

/// Verify a signature using the public key
pub fn verify(message: &[u8], signature: &MlDsaSignature, pk: &MlDsaPublicKey) -> bool {
    // Empty context per NIST spec for basic verification
    pk.0.verify(message, &signature.0, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_sign_verify() {
        let (pk, sk) = generate().unwrap();
        let message = b"Hello, quantum-resistant world!";

        let signature = sign(message, &sk).unwrap();
        assert!(verify(message, &signature, &pk));

        // Test with wrong message
        let wrong_message = b"Wrong message";
        assert!(!verify(wrong_message, &signature, &pk));
    }

    #[test]
    fn test_wrong_key_rejects_signature() {
        let (pk1, sk1) = generate().unwrap();
        let (_pk2, sk2) = generate().unwrap();
        let message = b"Signed by key 1";

        let sig = sign(message, &sk1).unwrap();
        // Verify with correct key succeeds
        assert!(verify(message, &sig, &pk1));

        // Verify with wrong key fails
        let (pk_wrong, _) = generate().unwrap();
        assert!(!verify(message, &sig, &pk_wrong));

        // Sign same message with different key produces different signature
        let sig2 = sign(message, &sk2).unwrap();
        assert_ne!(sig.as_bytes(), sig2.as_bytes());
    }

    #[test]
    fn test_empty_message_sign_verify() {
        let (pk, sk) = generate().unwrap();
        let message = b"";

        let signature = sign(message, &sk).unwrap();
        assert!(verify(message, &signature, &pk));
    }

    #[test]
    fn test_large_message_sign_verify() {
        let (pk, sk) = generate().unwrap();
        let message: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

        let signature = sign(&message, &sk).unwrap();
        assert!(verify(&message, &signature, &pk));

        // Tamper with one byte
        let mut tampered = message.clone();
        tampered[50_000] ^= 0x01;
        assert!(!verify(&tampered, &signature, &pk));
    }

    #[test]
    fn test_key_serialization() {
        let (pk, sk) = generate().unwrap();

        // Round-trip public key
        let pk_bytes = pk.as_bytes();
        let pk2 = MlDsaPublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk.as_bytes(), pk2.as_bytes());

        // Round-trip private key
        let sk_bytes = sk.as_bytes();
        let sk2 = MlDsaPrivateKey::from_bytes(&sk_bytes).unwrap();
        assert_eq!(sk.as_bytes(), sk2.as_bytes());
    }

    #[test]
    fn test_signature_serialization() {
        let (pk, sk) = generate().unwrap();
        let message = b"Test message";

        let sig = sign(message, &sk).unwrap();
        let sig_bytes = sig.as_bytes().to_vec();
        let sig2 = MlDsaSignature::from_bytes(&sig_bytes).unwrap();

        assert!(verify(message, &sig2, &pk));
    }

    #[test]
    fn test_invalid_key_sizes_rejected() {
        // Too short
        assert!(MlDsaPublicKey::from_bytes(&[0u8; 10]).is_err());
        assert!(MlDsaPrivateKey::from_bytes(&[0u8; 10]).is_err());
        assert!(MlDsaSignature::from_bytes(&[0u8; 10]).is_err());

        // Too long
        assert!(MlDsaPublicKey::from_bytes(&vec![0u8; PUBLIC_KEY_SIZE + 1]).is_err());
        assert!(MlDsaPrivateKey::from_bytes(&vec![0u8; PRIVATE_KEY_SIZE + 1]).is_err());
        assert!(MlDsaSignature::from_bytes(&vec![0u8; SIGNATURE_SIZE + 1]).is_err());

        // Empty
        assert!(MlDsaPublicKey::from_bytes(&[]).is_err());
        assert!(MlDsaPrivateKey::from_bytes(&[]).is_err());
        assert!(MlDsaSignature::from_bytes(&[]).is_err());
    }

    #[test]
    fn test_different_signatures_per_signing() {
        let (pk, sk) = generate().unwrap();
        let message = b"Determinism test";

        let sig1 = sign(message, &sk).unwrap();
        let sig2 = sign(message, &sk).unwrap();

        // Both should verify
        assert!(verify(message, &sig1, &pk));
        assert!(verify(message, &sig2, &pk));

        // ML-DSA-85 uses randomized signing, so signatures should differ
        // (This is a security property — deterministic sigs can leak key material)
        assert_ne!(sig1.as_bytes(), sig2.as_bytes());
    }
}
