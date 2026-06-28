// src/file/envelope.rs
//
// QVFile Envelope Format v1:
//
// Header:
//   [3 bytes] QVFILE_MAGIC ("QVF")
//   [1 byte]  QVKEY_VERSION (0x01)
//   [1 byte]  Flags: bit 0 = has_signature
//
// Body:
//   [4 bytes LE] kem_ciphertext_length
//   [N bytes]    kem_ciphertext
//   (if has_signature):
//     [4 bytes LE] signature_length
//     [N bytes]    signature
//   [8 bytes LE] aead_ciphertext_length
//   [N bytes]    aead_ciphertext

use crate::constants::*;
use crate::error::{QVError, QVResult};
use crate::kem::hybrid::{encapsulate, decapsulate};
use crate::sign::hybrid::{sign, verify};
use crate::sym::aead::{encrypt, decrypt};
use crate::keys::identity::{PQIdentity, PQPublicKey};
use zeroize::Zeroizing;

/// Envelope flags (stored as a single byte after magic+version).
const FLAG_HAS_SIGNATURE: u8 = 0x01;

pub struct PQFile;

impl PQFile {
    /// Encrypt `plaintext` for `recipient` and sign with `sender`.
    /// Returns a self-contained envelope blob with embedded signature.
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
        let shared_key = Zeroizing::new(*kem.shared_key);

        // 2. Sign the plaintext bound to the recipient's public key components to prevent signature replay/forwarding
        let mut signed_payload = Vec::with_capacity(plaintext.len() + 32 + 1568);
        signed_payload.extend_from_slice(plaintext);
        signed_payload.extend_from_slice(recipient.x25519_public.as_bytes());
        use fips203::traits::SerDes as KemSerDes;
        signed_payload.extend_from_slice(&KemSerDes::into_bytes(recipient.mlkem_public.clone()));

        let signature = sign(sender, &signed_payload)?;

        // 3. AEAD encrypt
        let aead_ct = encrypt(&shared_key, plaintext)?;

        // 4. Assemble signed envelope
        let flags = FLAG_HAS_SIGNATURE;
        let mut env = Vec::new();
        env.extend_from_slice(&QVFILE_MAGIC);
        env.push(QVKEY_VERSION);
        env.push(flags);

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
        // Header: magic(3) + version(1) + flags(1) = 5 bytes minimum
        if envelope.len() < 5 {
            return Err(QVError::InvalidKeyFormat("envelope too short".into()));
        }
        let magic: [u8; 3] = envelope[0..3].try_into().unwrap();
        if magic != QVFILE_MAGIC {
            return Err(QVError::InvalidMagic { expected: QVFILE_MAGIC, got: magic });
        }

        // Validate version byte (B3)
        let version = envelope[3];
        if version != QVKEY_VERSION {
            return Err(QVError::KeyVersionMismatch { expected: QVKEY_VERSION, got: version });
        }

        let flags = envelope[4];
        let has_signature = (flags & FLAG_HAS_SIGNATURE) != 0;

        let mut offset: usize = 5;

        // === KEM ciphertext ===
        offset = Self::check_offset(envelope, offset, 4, "KEM length")?;
        let kem_ct_len = u32::from_le_bytes(envelope[offset-4..offset].try_into().unwrap()) as usize;

        let kem_ct_end = offset.checked_add(kem_ct_len)
            .ok_or_else(|| QVError::InvalidKeyFormat("KEM ciphertext length overflow".into()))?;
        if envelope.len() < kem_ct_end {
            return Err(QVError::InvalidKeyFormat("envelope too short for KEM ciphertext".into()));
        }
        let kem_ct = &envelope[offset..kem_ct_end];
        offset = kem_ct_end;

        // === Signature (only present if FLAG_HAS_SIGNATURE is set) ===
        let signature = if has_signature {
            offset = Self::check_offset(envelope, offset, 4, "signature length")?;
            let sig_len = u32::from_le_bytes(envelope[offset-4..offset].try_into().unwrap()) as usize;

            let sig_end = offset.checked_add(sig_len)
                .ok_or_else(|| QVError::InvalidKeyFormat("signature length overflow".into()))?;
            if envelope.len() < sig_end {
                return Err(QVError::InvalidKeyFormat("envelope too short for signature".into()));
            }
            let sig = &envelope[offset..sig_end];
            offset = sig_end;
            Some(sig)
        } else {
            None
        };

        // === AEAD ciphertext ===
        offset = Self::check_offset(envelope, offset, 8, "AEAD length")?;
        let aead_len = u64::from_le_bytes(envelope[offset-8..offset].try_into().unwrap()) as usize;

        let aead_end = offset.checked_add(aead_len)
            .ok_or_else(|| QVError::InvalidKeyFormat("AEAD ciphertext length overflow".into()))?;
        if envelope.len() < aead_end {
            return Err(QVError::InvalidKeyFormat("envelope too short for AEAD ciphertext".into()));
        }
        let aead_ct = &envelope[offset..aead_end];

        // S9: Reject trailing data
        if envelope.len() != aead_end {
            return Err(QVError::InvalidKeyFormat("unexpected trailing data in envelope".into()));
        }

        // 1. Decapsulate
        let shared_key = decapsulate(recipient, kem_ct)?;

        // 2. Decrypt
        let plaintext = decrypt(&shared_key, aead_ct)?;

        // 3. Verify signature if present and sender key provided
        if let (Some(sig), Some(sender)) = (signature, sender_public) {
            let mut signed_payload = Vec::with_capacity(plaintext.len() + 32 + 1568);
            signed_payload.extend_from_slice(&plaintext);
            signed_payload.extend_from_slice(recipient.x25519_public.as_bytes());
            use fips203::traits::SerDes as KemSerDes;
            signed_payload.extend_from_slice(&KemSerDes::into_bytes(recipient.mlkem_public.clone()));

            verify(sender, &signed_payload, sig)?;
        }

        Ok(plaintext)
    }

    /// Encrypt without signing (anonymous sender).
    /// Produces a compact envelope without any signature section.
    pub fn encrypt(plaintext: &[u8], recipient: &PQPublicKey) -> QVResult<Vec<u8>> {
        if plaintext.len() as u64 > MAX_FILE_SIZE {
            return Err(QVError::FileTooLarge {
                size: plaintext.len() as u64,
                max:  MAX_FILE_SIZE,
            });
        }

        // 1. KEM: derive shared key + KEM ciphertext
        let kem = encapsulate(recipient)?;
        let shared_key = Zeroizing::new(*kem.shared_key);

        // 2. AEAD encrypt (no signature for anonymous mode)
        let aead_ct = encrypt(&shared_key, plaintext)?;

        // 3. Assemble unsigned envelope — no signature section at all
        let flags: u8 = 0x00; // no signature flag
        let mut env = Vec::new();
        env.extend_from_slice(&QVFILE_MAGIC);
        env.push(QVKEY_VERSION);
        env.push(flags);

        env.extend_from_slice(&(kem.ciphertext.len() as u32).to_le_bytes());
        env.extend_from_slice(&kem.ciphertext);

        // No signature section — skip directly to AEAD
        env.extend_from_slice(&(aead_ct.len() as u64).to_le_bytes());
        env.extend_from_slice(&aead_ct);

        Ok(env)
    }

    /// Helper: advance offset by `n` bytes, checking bounds.
    fn check_offset(envelope: &[u8], offset: usize, n: usize, field: &str) -> QVResult<usize> {
        let new_offset = offset.checked_add(n)
            .ok_or_else(|| QVError::InvalidKeyFormat(format!("{field} offset overflow")))?;
        if envelope.len() < new_offset {
            return Err(QVError::InvalidKeyFormat(format!("envelope too short for {field}")));
        }
        Ok(new_offset)
    }
}
