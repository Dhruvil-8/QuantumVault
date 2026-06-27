use crate::error::{QVError, QVResult};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};

/// Encrypt plaintext with a 32-byte key.
/// Returns: [nonce (12 bytes)] ++ [ciphertext + tag]
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> QVResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce  = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher.encrypt(&nonce, plaintext)
        .map_err(|e| QVError::Encryption(e.to_string()))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt ciphertext produced by `encrypt`.
pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> QVResult<Vec<u8>> {
    if ciphertext.len() < 12 {
        return Err(QVError::DecryptionFailed);
    }
    let nonce  = Nonce::from_slice(&ciphertext[..12]);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(nonce, &ciphertext[12..])
        .map_err(|_| QVError::DecryptionFailed)
}
