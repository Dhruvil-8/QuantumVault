use std::io::{Read, Write};

use crate::errors::VaultError;

/// AEAD nonce size (ChaCha20-Poly1305)
const NONCE_SIZE: usize = 12;

/// Decrypts a chunked encrypted stream.
///
/// Expected input format per chunk:
/// [PLAINTEXT_LEN u32]
/// [NONCE 12 bytes]
/// [CIPHERTEXT + TAG]
pub fn decrypt_stream<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    master_key: &[u8; 32],
    nonce_seed: &[u8; 32],
) -> Result<(), VaultError> {
    let mut chunk_index: u64 = 0;

    loop {
        // Read plaintext length
        let len = match read_u32(&mut reader) {
            Ok(v) => v as usize,
            Err(VaultError::UnexpectedEof) => break, // clean EOF
            Err(e) => return Err(e),
        };

        // Read nonce
        let mut nonce = [0u8; NONCE_SIZE];
        reader.read_exact(&mut nonce)?;

        // Ciphertext length = plaintext + AEAD tag (16 bytes)
        let mut ciphertext = vec![0u8; len + 16];
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

        let mut plaintext = match decrypt_chunk(master_key, &nonce, &ciphertext) {
            Ok(pt) => pt,
            Err(e) => {
                use zeroize::Zeroize;
                ciphertext.zeroize();
                return Err(e);
            }
        };

        if plaintext.len() != len {
            use zeroize::Zeroize;
            ciphertext.zeroize();
            plaintext.zeroize();
            return Err(VaultError::DecryptionFailed);
        }

        let write_res = writer.write_all(&plaintext);
        use zeroize::Zeroize;
        ciphertext.zeroize();
        plaintext.zeroize();
        write_res?;

        chunk_index += 1;
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