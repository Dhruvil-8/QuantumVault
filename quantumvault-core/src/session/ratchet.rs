// src/session/ratchet.rs

use crate::error::{QVError, QVResult};
use crate::sym::aead::{encrypt, decrypt};
use crate::kdf::hkdf::hkdf_sha3_512;
use crate::constants::SESSION_REKEY_THRESHOLD;
use zeroize::Zeroize;

pub struct PQSession {
    key: [u8; 32],
    nonce_counter: u64,
}

impl PQSession {
    pub fn new(shared_key: [u8; 32]) -> Self {
        Self {
            key: shared_key,
            nonce_counter: 0,
        }
    }

    /// Encrypt a message using the session key, then ratchet the key.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> QVResult<Vec<u8>> {
        if self.nonce_counter >= SESSION_REKEY_THRESHOLD {
            return Err(QVError::NonceExhausted);
        }
        
        let ct = encrypt(&self.key, plaintext)?;
        self.ratchet()?;
        self.nonce_counter += 1;
        Ok(ct)
    }

    /// Decrypt a message using the session key, then ratchet the key.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> QVResult<Vec<u8>> {
        if self.nonce_counter >= SESSION_REKEY_THRESHOLD {
            return Err(QVError::NonceExhausted);
        }
        
        let pt = decrypt(&self.key, ciphertext)?;
        self.ratchet()?;
        self.nonce_counter += 1;
        Ok(pt)
    }

    fn ratchet(&mut self) -> QVResult<()> {
        // Derive next session key
        let derived = hkdf_sha3_512(&self.key, None, b"ratchet", 32)?;
        self.key.copy_from_slice(&derived);
        Ok(())
    }
}

impl Drop for PQSession {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
