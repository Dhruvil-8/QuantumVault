use std::io::{Read, Write};

use crate::errors::VaultError;

/// Fixed chunk size: 8 MiB
pub const CHUNK_SIZE: usize = 8 * 1024 * 1024;

/// AEAD nonce size (ChaCha20-Poly1305)
const NONCE_SIZE: usize = 12;

/// Maximum number of chunks to prevent nonce-related issues
const MAX_CHUNK_COUNT: u64 = u32::MAX as u64;

struct ZeroizeBuffer(Vec<u8>);

impl Drop for ZeroizeBuffer {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

/// Encrypts a stream using chunked AEAD.
///
/// Output format per chunk:
/// [CIPHERTEXT_LEN u32]        — length of encrypted payload (including embedded length + tag)
/// [NONCE 12 bytes]            — per-chunk nonce derived from seed
/// [ENCRYPTED(LEN_U32 + PLAINTEXT) + TAG]  — AEAD-protected payload with length inside
///
/// The plaintext length is embedded inside the AEAD-protected payload to prevent
/// leaking exact file sizes to observers.
pub fn encrypt_stream<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    master_key: &[u8; 32],
    nonce_seed: &[u8; 32],
) -> Result<(), VaultError> {
    let mut buffer_guard = ZeroizeBuffer(vec![0u8; CHUNK_SIZE]);
    let buffer = &mut buffer_guard.0;
    let mut chunk_index: u64 = 0;

    loop {
        let read_len = reader.read(buffer)?;
        if read_len == 0 {
            break;
        }

        // Guard against chunk counter overflow to prevent nonce reuse
        if chunk_index >= MAX_CHUNK_COUNT {
            return Err(VaultError::ChunkOverflow);
        }

        let nonce = derive_nonce(nonce_seed, chunk_index)?;

        // Build plaintext payload: [LEN_U32 || PLAINTEXT]
        // This embeds the actual length inside the AEAD-protected region
        let mut payload = Vec::with_capacity(4 + read_len);
        payload.extend_from_slice(&(read_len as u32).to_be_bytes());
        payload.extend_from_slice(&buffer[..read_len]);

        let ciphertext = encrypt_chunk(
            master_key,
            &nonce,
            &payload,
        )?;

        // Zeroize the plaintext payload
        {
            use zeroize::Zeroize;
            payload.zeroize();
        }

        // Write ciphertext length (so decoder knows how many bytes to read)
        writer.write_all(&(ciphertext.len() as u32).to_be_bytes())?;

        // Write nonce
        writer.write_all(&nonce)?;

        // Write ciphertext (includes AEAD tag)
        writer.write_all(&ciphertext)?;

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

fn encrypt_chunk(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Key, Nonce,
    };

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|_| VaultError::EncryptionFailed)?;

    Ok(ciphertext)
}