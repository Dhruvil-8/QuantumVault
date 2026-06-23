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
    master_key: &[u8; 64],
    nonce_seed: &[u8; 64],
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
            Err(VaultError::UnexpectedEof) => return Err(VaultError::UnexpectedEof),
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

        // Verify nonce matches derived nonce (constant-time comparison)
        let expected_nonce = derive_nonce(nonce_seed, chunk_index)?;
        use subtle::ConstantTimeEq;
        if nonce.ct_eq(&expected_nonce).unwrap_u8() != 1 {
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

        let embedded_len =
            u32::from_be_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]]) as usize;

        if decrypted.len() - 4 != embedded_len {
            use zeroize::Zeroize;
            ciphertext.zeroize();
            decrypted.zeroize();
            return Err(VaultError::DecryptionFailed);
        }

        if embedded_len == 0 {
            use zeroize::Zeroize;
            ciphertext.zeroize();
            decrypted.zeroize();
            ensure_no_trailing_data(&mut reader)?;
            return Ok(());
        }

        let write_res = writer.write_all(&decrypted[4..]);
        use zeroize::Zeroize;
        ciphertext.zeroize();
        decrypted.zeroize();
        write_res?;

        chunk_index = chunk_index
            .checked_add(1)
            .ok_or(VaultError::ChunkOverflow)?;
    }
}

/* ---------------- internal helpers ---------------- */

fn derive_nonce(nonce_seed: &[u8; 64], index: u64) -> Result<[u8; NONCE_SIZE], VaultError> {
    use hkdf::Hkdf;
    use sha3::Sha3_512;

    let info = index.to_be_bytes();
    // Use proper HKDF extract+expand (RFC 5869) rather than from_prk(),
    // which expects input that has already been through the extract step.
    let hk = Hkdf::<Sha3_512>::new(None, nonce_seed);
    let mut nonce = [0u8; NONCE_SIZE];
    hk.expand(&info, &mut nonce)
        .map_err(|_| VaultError::CryptoError)?;
    Ok(nonce)
}

fn decrypt_chunk(
    key: &[u8; 64],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    use chacha20poly1305::{
        ChaCha20Poly1305, Key, Nonce,
        aead::{Aead, KeyInit},
    };

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..32]));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| VaultError::DecryptionFailed)?;

    Ok(plaintext)
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32, VaultError> {
    let mut buf = [0u8; 4];
    match r.read_exact(&mut buf) {
        Ok(()) => Ok(u32::from_be_bytes(buf)),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(VaultError::UnexpectedEof),
        Err(e) => Err(VaultError::Io(e)),
    }
}

fn ensure_no_trailing_data<R: Read>(reader: &mut R) -> Result<(), VaultError> {
    let mut trailing = [0u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => Ok(()),
        Ok(_) => Err(VaultError::InvalidFormat),
        Err(e) => Err(VaultError::Io(e)),
    }
}
