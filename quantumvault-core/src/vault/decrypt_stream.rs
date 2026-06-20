use std::io::{Read, Write};

use crate::errors::VaultError;

/// AEAD nonce size (ChaCha20-Poly1305)
const NONCE_SIZE: usize = 12;

/// Maximum allowed ciphertext chunk size (chunk data + 4 byte length prefix + 16 byte tag)
/// Based on CHUNK_SIZE from encrypt_stream (8 MiB) + 4 + 16
const MAX_CIPHERTEXT_SIZE: usize = 8 * 1024 * 1024 + 4 + 16;

/// Maximum number of chunks to prevent nonce-related issues
const MAX_CHUNK_COUNT: u64 = u32::MAX as u64;

/// Decrypts a chunked encrypted stream.
///
/// Expected input format per chunk:
/// [CIPHERTEXT_LEN u32]        — total length of encrypted payload
/// [NONCE 12 bytes]            — per-chunk nonce
/// [ENCRYPTED(LEN_U32 + PLAINTEXT) + TAG]  — AEAD-protected payload
///
/// The plaintext length is embedded inside the AEAD-protected payload.
pub fn decrypt_stream<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    master_key: &[u8; 32],
    nonce_seed: &[u8; 32],
) -> Result<(), VaultError> {
    let mut chunk_index: u64 = 0;

    loop {
        // Guard against chunk counter overflow
        if chunk_index >= MAX_CHUNK_COUNT {
            return Err(VaultError::ChunkOverflow);
        }

        // Read ciphertext length
        let ct_len = match read_u32(&mut reader) {
            Ok(v) => v as usize,
            Err(VaultError::UnexpectedEof) => break, // clean EOF
            Err(e) => return Err(e),
        };

        // Validate ciphertext size to prevent memory exhaustion attacks
        if ct_len > MAX_CIPHERTEXT_SIZE {
            return Err(VaultError::ChunkTooLarge);
        }
        // Ciphertext must be at least 4 (embedded length) + 16 (AEAD tag) = 20 bytes
        if ct_len < 20 {
            return Err(VaultError::InvalidFormat);
        }

        // Read nonce
        let mut nonce = [0u8; NONCE_SIZE];
        reader.read_exact(&mut nonce)?;

        // Read ciphertext
        let mut ciphertext = vec![0u8; ct_len];
        if let Err(e) = reader.read_exact(&mut ciphertext) {
            use zeroize::Zeroize;
            ciphertext.zeroize();
            return Err(e.into());
        }

        // Verify nonce matches derived nonce
        let expected_nonce = derive_nonce(nonce_seed, chunk_index)?;
        if nonce != expected_nonce {
            use zeroize::Zeroize;
            ciphertext.zeroize();
            return Err(VaultError::DecryptionFailed);
        }

        let mut decrypted = match decrypt_chunk(master_key, &nonce, &ciphertext) {
            Ok(pt) => pt,
            Err(e) => {
                use zeroize::Zeroize;
                ciphertext.zeroize();
                return Err(e);
            }
        };

        // Extract embedded length from decrypted payload: [LEN_U32 || PLAINTEXT]
        if decrypted.len() < 4 {
            use zeroize::Zeroize;
            ciphertext.zeroize();
            decrypted.zeroize();
            return Err(VaultError::DecryptionFailed);
        }

        let embedded_len = u32::from_be_bytes([
            decrypted[0], decrypted[1], decrypted[2], decrypted[3],
        ]) as usize;

        if decrypted.len() - 4 != embedded_len {
            use zeroize::Zeroize;
            ciphertext.zeroize();
            decrypted.zeroize();
            return Err(VaultError::DecryptionFailed);
        }

        let write_res = writer.write_all(&decrypted[4..]);
        use zeroize::Zeroize;
        ciphertext.zeroize();
        decrypted.zeroize();
        write_res?;

        chunk_index = chunk_index.checked_add(1)
            .ok_or(VaultError::ChunkOverflow)?;
    }

    Ok(())
}

/* ---------------- internal helpers ---------------- */

fn derive_nonce(
    nonce_seed: &[u8; 32],
    index: u64,
) -> Result<[u8; NONCE_SIZE], VaultError> {
    let mut info = [0u8; 8];
    info.copy_from_slice(&index.to_be_bytes());

    let full = crate::crypto::kdf::hkdf_expand(nonce_seed, &info, NONCE_SIZE)?;
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&full);
    Ok(nonce)
}

fn decrypt_chunk(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Key, Nonce,
    };

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| VaultError::DecryptionFailed)?;

    Ok(plaintext)
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32, VaultError> {
    let mut buf = [0u8; 4];
    match r.read_exact(&mut buf) {
        Ok(()) => Ok(u32::from_be_bytes(buf)),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            Err(VaultError::UnexpectedEof)
        }
        Err(e) => Err(VaultError::Io(e)),
    }
}