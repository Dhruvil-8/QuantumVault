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
///
/// A final authenticated zero-length chunk is always written as an EOF marker.
/// This prevents a vault truncated exactly at a chunk boundary from decrypting
/// successfully as a shorter plaintext.
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
        // Fill the buffer completely before encrypting a chunk.
        // A single read() may return fewer bytes than requested (pipes,
        // network FS, OS scheduling), so we loop until full or EOF.
        let read_len = read_full(&mut reader, buffer)?;
        if read_len == 0 {
            break;
        }

        // Guard against chunk counter overflow to prevent nonce reuse
        if chunk_index >= MAX_CHUNK_COUNT {
            return Err(VaultError::ChunkOverflow);
        }

        // Build plaintext payload: [LEN_U32 || PLAINTEXT]
        // This embeds the actual length inside the AEAD-protected region
        let mut payload = Vec::with_capacity(4 + read_len);
        payload.extend_from_slice(&(read_len as u32).to_be_bytes());
        payload.extend_from_slice(&buffer[..read_len]);

        write_encrypted_payload(
            &mut writer,
            master_key,
            nonce_seed,
            chunk_index,
            &mut payload,
        )?;

        chunk_index = chunk_index
            .checked_add(1)
            .ok_or(VaultError::ChunkOverflow)?;
    }

    if chunk_index >= MAX_CHUNK_COUNT {
        return Err(VaultError::ChunkOverflow);
    }

    let mut final_payload = 0u32.to_be_bytes().to_vec();
    write_encrypted_payload(
        &mut writer,
        master_key,
        nonce_seed,
        chunk_index,
        &mut final_payload,
    )?;

    Ok(())
}

/* ---------------- internal helpers ---------------- */

fn write_encrypted_payload<W: Write>(
    writer: &mut W,
    master_key: &[u8; 32],
    nonce_seed: &[u8; 32],
    chunk_index: u64,
    payload: &mut Vec<u8>,
) -> Result<(), VaultError> {
    let nonce = derive_nonce(nonce_seed, chunk_index)?;

    let ciphertext = encrypt_chunk(master_key, &nonce, payload)?;

    use zeroize::Zeroize;
    payload.zeroize();

    writer.write_all(&(ciphertext.len() as u32).to_be_bytes())?;
    writer.write_all(&nonce)?;
    writer.write_all(&ciphertext)?;

    Ok(())
}

fn derive_nonce(nonce_seed: &[u8; 32], index: u64) -> Result<[u8; NONCE_SIZE], VaultError> {
    use hkdf::Hkdf;
    use sha3::Sha3_256;

    let info = index.to_be_bytes();
    // Use proper HKDF extract+expand (RFC 5869) rather than from_prk(),
    // which expects input that has already been through the extract step.
    let hk = Hkdf::<Sha3_256>::new(None, nonce_seed);
    let mut nonce = [0u8; NONCE_SIZE];
    hk.expand(&info, &mut nonce)
        .map_err(|_| VaultError::CryptoError)?;
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

/// Read from `reader` until `buf` is completely filled or EOF is reached.
/// Returns the number of bytes actually read (may be less than `buf.len()` only at EOF).
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}
