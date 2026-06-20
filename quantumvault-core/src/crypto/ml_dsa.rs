//! ML-DSA-65 Module (NIST FIPS 204)
//!
//! This module provides quantum-resistant digital signatures using the
//! Module-Lattice-Based Digital Signature Algorithm standardized by NIST.

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};

/// Size constants for ML-DSA-65
pub const PUBLIC_KEY_SIZE: usize = 1952;
pub const PRIVATE_KEY_SIZE: usize = 4032;
pub const SIGNATURE_SIZE: usize = 3309;

/// ML-DSA-65 Public Key (for verification)
#[derive(Clone)]
pub struct MlDsaPublicKey(pub ml_dsa_65::PublicKey);

/// ML-DSA-65 Private Key (for signing)
pub struct MlDsaPrivateKey(pub ml_dsa_65::PrivateKey);

/// ML-DSA-65 Signature
#[derive(Clone)]
pub struct MlDsaSignature(pub [u8; SIGNATURE_SIZE]);

impl MlDsaPublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != PUBLIC_KEY_SIZE {
            return Err("Invalid public key size");
        }
        let arr: [u8; PUBLIC_KEY_SIZE] = bytes.try_into()
            .map_err(|_| "Invalid public key size")?;
        let pk = ml_dsa_65::PublicKey::try_from_bytes(arr)
            .map_err(|_| "Invalid public key")?;
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
        let arr: [u8; PRIVATE_KEY_SIZE] = bytes.try_into()
            .map_err(|_| "Invalid private key size")?;
        let sk = ml_dsa_65::PrivateKey::try_from_bytes(arr)
            .map_err(|_| "Invalid private key")?;
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
        let arr: [u8; SIGNATURE_SIZE] = bytes.try_into()
            .map_err(|_| "Invalid signature size")?;
        Ok(Self(arr))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }
}

/// Generate a new ML-DSA-65 keypair
pub fn generate() -> (MlDsaPublicKey, MlDsaPrivateKey) {
    let (pk, sk) = ml_dsa_65::try_keygen().expect("ML-DSA keygen failed");
    (MlDsaPublicKey(pk), MlDsaPrivateKey(sk))
}

/// Sign a message using the private key
pub fn sign(message: &[u8], sk: &MlDsaPrivateKey) -> MlDsaSignature {
    // Empty context per NIST spec for basic signatures
    let sig_bytes = sk.0.try_sign(message, &[]).expect("ML-DSA signing failed");
    MlDsaSignature(sig_bytes)
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
        let (pk, sk) = generate();
        let message = b"Hello, quantum-resistant world!";
        
        let signature = sign(message, &sk);
        assert!(verify(message, &signature, &pk));
        
        // Test with wrong message
        let wrong_message = b"Wrong message";
        assert!(!verify(wrong_message, &signature, &pk));
    }

    #[test]
    fn test_key_serialization() {
        let (pk, sk) = generate();
        
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
        let (pk, sk) = generate();
        let message = b"Test message";
        
        let sig = sign(message, &sk);
        let sig_bytes = sig.as_bytes().to_vec();
        let sig2 = MlDsaSignature::from_bytes(&sig_bytes).unwrap();
        
        assert!(verify(message, &sig2, &pk));
    }
}
