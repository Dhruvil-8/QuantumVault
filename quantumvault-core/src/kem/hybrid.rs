// src/kem/hybrid.rs
//
// Hybrid key encapsulation: X25519 + ML-KEM-1024.
// Both shared secrets are combined via HKDF-SHA3-512.
// Neither classical nor PQ alone is sufficient — attacker must break both.

use crate::constants::*;
use crate::error::{QVError, QVResult};
use crate::kdf::hkdf::hkdf_sha3_512;
use crate::keys::identity::{PQIdentity, PQPublicKey};
use fips203::ml_kem_1024;
use fips203::traits::{Encaps, Decaps, SerDes};
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
    let (mlkem_ss, mlkem_ct): (fips203::SharedSecretKey, fips203::ml_kem_1024::CipherText) = 
        recipient.mlkem_public.try_encaps()
            .map_err(|e: &'static str| QVError::Encapsulation(e.to_string()))?;

    // === Combine via HKDF-SHA3-512 ===
    // IKM = x25519_ss || mlkem_ss (64 bytes total)
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(&x25519_ss);
    ikm[32..].copy_from_slice(&mlkem_ss.clone().into_bytes());

    // Salt = x25519_ephemeral_pub || mlkem_ciphertext (prevents KEM mixing attacks)
    let mut salt = Vec::with_capacity(32 + MLKEM1024_CIPHERTEXT_SIZE);
    salt.extend_from_slice(ephemeral_public.as_bytes());
    salt.extend_from_slice(&mlkem_ct.clone().into_bytes());

    let derived = hkdf_sha3_512(ikm.as_ref(), Some(&salt), HKDF_INFO_KEM, 32)?;
    let mut shared_key = Zeroizing::new([0u8; 32]);
    shared_key.copy_from_slice(&derived);

    // Ciphertext to send
    let mut ciphertext = Vec::with_capacity(32 + MLKEM1024_CIPHERTEXT_SIZE);
    ciphertext.extend_from_slice(ephemeral_public.as_bytes());
    ciphertext.extend_from_slice(&mlkem_ct.into_bytes());

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
    let mut ct_bytes = [0u8; MLKEM1024_CIPHERTEXT_SIZE];
    ct_bytes.copy_from_slice(&ciphertext[32..]);
    let mlkem_ct = ml_kem_1024::CipherText::try_from_bytes(ct_bytes)
        .map_err(|e: &'static str| QVError::Decapsulation(e.to_string()))?;
    
    let mlkem_ss = identity.mlkem_secret.try_decaps(&mlkem_ct)
        .map_err(|e: &'static str| QVError::Decapsulation(e.to_string()))?;

    // === Combine via HKDF-SHA3-512 ===
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(&x25519_ss);
    ikm[32..].copy_from_slice(&mlkem_ss.into_bytes());

    let derived = hkdf_sha3_512(ikm.as_ref(), Some(ciphertext), HKDF_INFO_KEM, 32)?;
    let mut shared_key = Zeroizing::new([0u8; 32]);
    shared_key.copy_from_slice(&derived);

    Ok(shared_key)
}
