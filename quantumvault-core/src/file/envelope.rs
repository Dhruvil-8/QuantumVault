// src/file/envelope.rs

use crate::constants::*;
use crate::error::{QVError, QVResult};
use crate::kem::hybrid::{encapsulate, decapsulate};
use crate::sign::hybrid::{sign, verify};
use crate::sym::aead::{encrypt, decrypt};
use crate::keys::identity::{PQIdentity, PQPublicKey};

pub struct PQFile;

impl PQFile {
    /// Encrypt `plaintext` for `recipient` and sign with `sender`.
    /// Returns a self-contained envelope blob.
    pub fn encrypt_and_sign(
        plaintext: &[u8],
        recipient: &PQPublicKey,
        sender:    &PQIdentity,
    ) -> QVResult<Vec<u8>> {
        if plaintext.len() as u64 > MAX_FILE_SIZE {
            return Err(QVError::FileTooLarge {
                size: plaintext.len() as u64,
                max:  MAX_FILE_SIZE,
            });
        }

        // 1. KEM: derive shared key + KEM ciphertext
        let kem = encapsulate(recipient)?;
        let shared_key: [u8; 32] = *kem.shared_key;

        // 2. Sign the plaintext
        let signature = sign(sender, plaintext)?;

        // 3. AEAD encrypt
        let aead_ct = encrypt(&shared_key, plaintext)?;

        // 4. Assemble envelope
        let mut env = Vec::new();
        env.extend_from_slice(&QVFILE_MAGIC);
        env.push(QVKEY_VERSION);

        env.extend_from_slice(&(kem.ciphertext.len() as u32).to_le_bytes());
        env.extend_from_slice(&kem.ciphertext);

        env.extend_from_slice(&(signature.len() as u32).to_le_bytes());
        env.extend_from_slice(&signature);

        env.extend_from_slice(&(aead_ct.len() as u64).to_le_bytes());
        env.extend_from_slice(&aead_ct);

        Ok(env)
    }

    /// Decrypt a PQFile envelope using `recipient_identity`.
    /// Optionally verify sender's signature if `sender_public` is provided.
    pub fn decrypt_and_verify(
        envelope:         &[u8],
        recipient:        &PQIdentity,
        sender_public:    Option<&PQPublicKey>,
    ) -> QVResult<Vec<u8>> {
        let mut offset: usize = 4; // magic + version

        // Magic + version
        if envelope.len() < 4 { return Err(QVError::InvalidKeyFormat("envelope too short".into())); }
        let magic: [u8; 3] = envelope[0..3].try_into().unwrap();
        if magic != QVFILE_MAGIC {
            return Err(QVError::InvalidMagic { expected: QVFILE_MAGIC, got: magic });
        }

        // KEM ciphertext
        let kem_len_check = match offset.checked_add(4) {
            Some(val) => val,
            None => return Err(QVError::InvalidKeyFormat("offset overflow".into())),
        };
        if envelope.len() < kem_len_check { return Err(QVError::InvalidKeyFormat("envelope too short".into())); }
        let kem_ct_len = u32::from_le_bytes(envelope[offset..offset+4].try_into().unwrap()) as usize;
        offset = kem_len_check;

        let kem_ct_end = match offset.checked_add(kem_ct_len) {
            Some(val) => val,
            None => return Err(QVError::InvalidKeyFormat("KEM ciphertext length overflow".into())),
        };
        if envelope.len() < kem_ct_end { return Err(QVError::InvalidKeyFormat("envelope too short".into())); }
        let kem_ct = &envelope[offset..kem_ct_end];
        offset = kem_ct_end;

        // Signature
        let sig_len_check = match offset.checked_add(4) {
            Some(val) => val,
            None => return Err(QVError::InvalidKeyFormat("offset overflow".into())),
        };
        if envelope.len() < sig_len_check { return Err(QVError::InvalidKeyFormat("envelope too short".into())); }
        let sig_len = u32::from_le_bytes(envelope[offset..offset+4].try_into().unwrap()) as usize;
        offset = sig_len_check;

        let sig_end = match offset.checked_add(sig_len) {
            Some(val) => val,
            None => return Err(QVError::InvalidKeyFormat("signature length overflow".into())),
        };
        if envelope.len() < sig_end { return Err(QVError::InvalidKeyFormat("envelope too short".into())); }
        let signature = &envelope[offset..sig_end];
        offset = sig_end;

        // AEAD ciphertext
        let aead_len_check = match offset.checked_add(8) {
            Some(val) => val,
            None => return Err(QVError::InvalidKeyFormat("offset overflow".into())),
        };
        if envelope.len() < aead_len_check { return Err(QVError::InvalidKeyFormat("envelope too short".into())); }
        let aead_len = u64::from_le_bytes(envelope[offset..offset+8].try_into().unwrap()) as usize;
        offset = aead_len_check;

        let aead_end = match offset.checked_add(aead_len) {
            Some(val) => val,
            None => return Err(QVError::InvalidKeyFormat("AEAD ciphertext length overflow".into())),
        };
        if envelope.len() < aead_end { return Err(QVError::InvalidKeyFormat("envelope too short".into())); }
        let aead_ct = &envelope[offset..aead_end];

        // 1. Decapsulate
        let shared_key = decapsulate(recipient, kem_ct)?;
        let key: [u8; 32] = *shared_key;

        // 2. Decrypt
        let plaintext = decrypt(&key, aead_ct)?;

        // 3. Verify signature if sender provided
        if let Some(sender) = sender_public {
            verify(sender, &plaintext, signature)?;
        }

        Ok(plaintext)
    }

    /// Encrypt without signing (anonymous sender).
    pub fn encrypt(plaintext: &[u8], recipient: &PQPublicKey) -> QVResult<Vec<u8>> {
        // Use a throwaway identity for the signature slot
        let anon = PQIdentity::generate()?;
        Self::encrypt_and_sign(plaintext, recipient, &anon)
    }
}
