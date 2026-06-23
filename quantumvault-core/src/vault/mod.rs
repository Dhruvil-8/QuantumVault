//! Vault Operations
//!
//! This module provides the high-level encrypt/decrypt operations
//! for QuantumVault files (.qvault).

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::errors::VaultError;
use rand::{RngCore, rngs::OsRng};

mod decrypt_stream;
mod encrypt_stream;
mod header;

pub use decrypt_stream::decrypt_stream;
pub use encrypt_stream::encrypt_stream;
pub use header::{QVLT_MAGIC, VAULT_VERSION, VaultHeader};

use crate::crypto::identity::Identity;
use crate::crypto::public::{RecipientPublic, SenderPublic};

/// Encrypt a file into a QuantumVault
///
/// # Arguments
/// * `input` - Path to the plaintext input file
/// * `output` - Path for the encrypted output file (.qvault)
/// * `sender` - The sender's identity (for signing)
/// * `recipient` - The recipient's public keys (for encryption)
pub fn encrypt_file(
    input: &Path,
    output: &Path,
    sender: &Identity,
    recipient: &RecipientPublic,
) -> Result<(), VaultError> {
    // Open files
    let input_file = File::open(input)?;
    let output_file = File::create(output)?;

    let reader = BufReader::new(input_file);
    let mut writer = BufWriter::new(output_file);

    // Create and write header
    let (header, mut master_key) = VaultHeader::create(sender, recipient)?;
    header.write_to(&mut writer)?;

    // Encrypt stream
    let res = encrypt_stream::encrypt_stream(reader, &mut writer, &master_key, &header.nonce_seed);
    use zeroize::Zeroize;
    master_key.zeroize();

    res?;
    writer.flush()?;
    Ok(())
}

/// Decrypt a QuantumVault back to a file
///
/// Uses a temporary file for output and atomically renames on success.
/// This prevents leaving partial/corrupted output if decryption fails mid-stream.
///
/// # Arguments
/// * `vault` - Path to the encrypted vault file
/// * `output` - Path for the decrypted output file
/// * `recipient` - The recipient's identity (for decryption)
/// * `sender_pub` - The sender's public signing key (for verification)
pub fn decrypt_file(
    vault: &Path,
    output: &Path,
    recipient: &Identity,
    sender_pub: &SenderPublic,
) -> Result<(), VaultError> {
    let vault_file = File::open(vault)?;
    let (temp_path, temp_file) = create_temp_output_file(output)?;

    let mut reader = BufReader::new(vault_file);
    let mut writer = BufWriter::new(temp_file);

    // Read and verify header
    let (header, mut master_key) = match VaultHeader::read_from(&mut reader, recipient, sender_pub)
    {
        Ok(result) => result,
        Err(e) => {
            drop(writer);
            let _ = fs::remove_file(&temp_path);
            return Err(e);
        }
    };

    // Decrypt stream
    let res =
        decrypt_stream::decrypt_stream(&mut reader, &mut writer, &master_key, &header.nonce_seed);
    use zeroize::Zeroize;
    master_key.zeroize();

    if let Err(e) = res {
        // Clean up temp file on failure
        drop(writer);
        let _ = fs::remove_file(&temp_path);
        return Err(e);
    }

    writer.flush()?;
    drop(writer);

    // Atomically rename temp file to final output
    fs::rename(&temp_path, output).map_err(|e| {
        // If rename fails, try to clean up
        let _ = fs::remove_file(&temp_path);
        VaultError::Io(e)
    })?;

    Ok(())
}

fn create_temp_output_file(output: &Path) -> Result<(PathBuf, File), VaultError> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let file_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("output");

    for _ in 0..16 {
        let suffix = OsRng.next_u64();
        let temp_path = parent.join(format!(".{}.{}.qvault_tmp", file_name, suffix));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => return Ok((temp_path, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(VaultError::Io(e)),
        }
    }

    Err(VaultError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not create a unique temporary output file",
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_test_dir(prefix: &str) -> std::path::PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = temp_dir().join(format!("qv_{}_{}", prefix, timestamp));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ───── Basic roundtrip tests ─────

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let sender = Identity::generate().unwrap();
        let recipient = Identity::generate().unwrap();
        let test_dir = make_test_dir("roundtrip");

        let plaintext = b"Hello, quantum-resistant world! This is a test message.";
        let input_path = test_dir.join("test_input.txt");
        let vault_path = test_dir.join("test_input.txt.qvault");
        let output_path = test_dir.join("test_output.txt");

        fs::write(&input_path, plaintext).unwrap();

        encrypt_file(
            &input_path,
            &vault_path,
            &sender,
            &recipient.recipient_public(),
        )
        .expect("Encryption failed");

        assert!(vault_path.exists());
        let vault_size = fs::metadata(&vault_path).unwrap().len();
        assert!(vault_size > plaintext.len() as u64);

        decrypt_file(
            &vault_path,
            &output_path,
            &recipient,
            &sender.sender_public(),
        )
        .expect("Decryption failed");

        let decrypted = fs::read(&output_path).unwrap();
        assert_eq!(decrypted, plaintext);
        assert!(!test_dir.join("test_output.qvault_tmp").exists());

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_empty_file_roundtrip() {
        let sender = Identity::generate().unwrap();
        let recipient = Identity::generate().unwrap();
        let test_dir = make_test_dir("empty");

        let input_path = test_dir.join("empty.txt");
        let vault_path = test_dir.join("empty.txt.qvault");
        let output_path = test_dir.join("empty_out.txt");

        fs::write(&input_path, b"").unwrap();

        encrypt_file(
            &input_path,
            &vault_path,
            &sender,
            &recipient.recipient_public(),
        )
        .expect("Encrypt empty failed");

        decrypt_file(
            &vault_path,
            &output_path,
            &recipient,
            &sender.sender_public(),
        )
        .expect("Decrypt empty failed");

        let decrypted = fs::read(&output_path).unwrap();
        assert_eq!(decrypted, b"");

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_single_byte_roundtrip() {
        let sender = Identity::generate().unwrap();
        let recipient = Identity::generate().unwrap();
        let test_dir = make_test_dir("single_byte");

        let input_path = test_dir.join("one.bin");
        let vault_path = test_dir.join("one.bin.qvault");
        let output_path = test_dir.join("one_out.bin");

        fs::write(&input_path, &[0x42]).unwrap();

        encrypt_file(
            &input_path,
            &vault_path,
            &sender,
            &recipient.recipient_public(),
        )
        .unwrap();

        decrypt_file(
            &vault_path,
            &output_path,
            &recipient,
            &sender.sender_public(),
        )
        .unwrap();

        assert_eq!(fs::read(&output_path).unwrap(), vec![0x42]);

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_binary_data_all_byte_values() {
        let sender = Identity::generate().unwrap();
        let recipient = Identity::generate().unwrap();
        let test_dir = make_test_dir("binary");

        // Create binary file with all 256 byte values repeated
        let mut data: Vec<u8> = Vec::with_capacity(256 * 4);
        for _ in 0..4 {
            for b in 0u8..=255 {
                data.push(b);
            }
        }

        let input_path = test_dir.join("binary.bin");
        let vault_path = test_dir.join("binary.bin.qvault");
        let output_path = test_dir.join("binary_out.bin");

        fs::write(&input_path, &data).unwrap();

        encrypt_file(
            &input_path,
            &vault_path,
            &sender,
            &recipient.recipient_public(),
        )
        .unwrap();

        decrypt_file(
            &vault_path,
            &output_path,
            &recipient,
            &sender.sender_public(),
        )
        .unwrap();

        assert_eq!(fs::read(&output_path).unwrap(), data);

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_large_multi_chunk_roundtrip() {
        let sender = Identity::generate().unwrap();
        let recipient = Identity::generate().unwrap();
        let test_dir = make_test_dir("large");

        // 2x chunk size + partial = tests multi-chunk + final partial chunk
        let size = encrypt_stream::CHUNK_SIZE * 2 + 12345;
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

        let input_path = test_dir.join("large.bin");
        let vault_path = test_dir.join("large.bin.qvault");
        let output_path = test_dir.join("large_out.bin");

        fs::write(&input_path, &data).unwrap();

        encrypt_file(
            &input_path,
            &vault_path,
            &sender,
            &recipient.recipient_public(),
        )
        .expect("Large encrypt failed");

        decrypt_file(
            &vault_path,
            &output_path,
            &recipient,
            &sender.sender_public(),
        )
        .expect("Large decrypt failed");

        let decrypted = fs::read(&output_path).unwrap();
        assert_eq!(decrypted.len(), data.len());
        assert_eq!(decrypted, data);

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_exact_chunk_boundary() {
        let sender = Identity::generate().unwrap();
        let recipient = Identity::generate().unwrap();
        let test_dir = make_test_dir("boundary");

        // Exactly 1 chunk size — tests boundary handling
        let data: Vec<u8> = vec![0xAB; encrypt_stream::CHUNK_SIZE];

        let input_path = test_dir.join("boundary.bin");
        let vault_path = test_dir.join("boundary.bin.qvault");
        let output_path = test_dir.join("boundary_out.bin");

        fs::write(&input_path, &data).unwrap();

        encrypt_file(
            &input_path,
            &vault_path,
            &sender,
            &recipient.recipient_public(),
        )
        .unwrap();

        decrypt_file(
            &vault_path,
            &output_path,
            &recipient,
            &sender.sender_public(),
        )
        .unwrap();

        assert_eq!(fs::read(&output_path).unwrap(), data);

        let _ = fs::remove_dir_all(&test_dir);
    }

    // ───── Authentication / security tests ─────

    #[test]
    fn test_wrong_recipient_fails() {
        let sender = Identity::generate().unwrap();
        let recipient = Identity::generate().unwrap();
        let wrong_recipient = Identity::generate().unwrap();
        let test_dir = make_test_dir("wrong_recip");

        let input_path = test_dir.join("test.txt");
        let vault_path = test_dir.join("test.qvault");
        let output_path = test_dir.join("test_out.txt");

        fs::write(&input_path, b"Secret data").unwrap();

        encrypt_file(
            &input_path,
            &vault_path,
            &sender,
            &recipient.recipient_public(),
        )
        .unwrap();

        let result = decrypt_file(
            &vault_path,
            &output_path,
            &wrong_recipient,
            &sender.sender_public(),
        );

        assert!(result.is_err());
        assert!(!test_dir.join("test_out.qvault_tmp").exists());

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_wrong_sender_signature_rejected() {
        let sender = Identity::generate().unwrap();
        let wrong_sender = Identity::generate().unwrap();
        let recipient = Identity::generate().unwrap();
        let test_dir = make_test_dir("wrong_sender");

        let input_path = test_dir.join("test.txt");
        let vault_path = test_dir.join("test.qvault");
        let output_path = test_dir.join("test_out.txt");

        fs::write(&input_path, b"Authenticated data").unwrap();

        // Encrypt with real sender
        encrypt_file(
            &input_path,
            &vault_path,
            &sender,
            &recipient.recipient_public(),
        )
        .unwrap();

        // Try to decrypt with wrong sender's public key
        let result = decrypt_file(
            &vault_path,
            &output_path,
            &recipient,
            &wrong_sender.sender_public(),
        );

        assert!(result.is_err(), "Should reject wrong sender signature");
        // Verify it's a signature error specifically
        match result.unwrap_err() {
            VaultError::InvalidSignature => {}
            other => panic!("Expected InvalidSignature, got: {:?}", other),
        }

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_tampered_ciphertext_detected() {
        let sender = Identity::generate().unwrap();
        let recipient = Identity::generate().unwrap();
        let test_dir = make_test_dir("tamper_ct");

        let input_path = test_dir.join("test.txt");
        let vault_path = test_dir.join("test.qvault");
        let output_path = test_dir.join("test_out.txt");

        fs::write(&input_path, b"Integrity-protected data").unwrap();

        encrypt_file(
            &input_path,
            &vault_path,
            &sender,
            &recipient.recipient_public(),
        )
        .unwrap();

        // Tamper with the encrypted payload (last 100 bytes are in ciphertext region)
        let mut vault_data = fs::read(&vault_path).unwrap();
        let len = vault_data.len();
        if len > 100 {
            vault_data[len - 50] ^= 0xFF; // flip bits in ciphertext
        }
        fs::write(&vault_path, &vault_data).unwrap();

        let result = decrypt_file(
            &vault_path,
            &output_path,
            &recipient,
            &sender.sender_public(),
        );

        assert!(result.is_err(), "Tampered ciphertext should be rejected");

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_tampered_magic_rejected() {
        let sender = Identity::generate().unwrap();
        let recipient = Identity::generate().unwrap();
        let test_dir = make_test_dir("tamper_magic");

        let input_path = test_dir.join("test.txt");
        let vault_path = test_dir.join("test.qvault");
        let output_path = test_dir.join("test_out.txt");

        fs::write(&input_path, b"data").unwrap();

        encrypt_file(
            &input_path,
            &vault_path,
            &sender,
            &recipient.recipient_public(),
        )
        .unwrap();

        // Tamper with magic bytes
        let mut vault_data = fs::read(&vault_path).unwrap();
        vault_data[0] = b'X'; // break "QVLT" magic
        fs::write(&vault_path, &vault_data).unwrap();

        let result = decrypt_file(
            &vault_path,
            &output_path,
            &recipient,
            &sender.sender_public(),
        );

        assert!(matches!(result, Err(VaultError::InvalidFormat)));

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_tampered_flags_rejected() {
        let sender = Identity::generate().unwrap();
        let recipient = Identity::generate().unwrap();
        let test_dir = make_test_dir("tamper_flags");

        let input_path = test_dir.join("test.txt");
        let vault_path = test_dir.join("test.qvault");
        let output_path = test_dir.join("test_out.txt");

        fs::write(&input_path, b"data").unwrap();

        encrypt_file(
            &input_path,
            &vault_path,
            &sender,
            &recipient.recipient_public(),
        )
        .unwrap();

        // Change flags bytes (bytes 6-7 after magic and version).
        let mut vault_data = fs::read(&vault_path).unwrap();
        vault_data[7] = 0x01;
        fs::write(&vault_path, &vault_data).unwrap();

        let result = decrypt_file(
            &vault_path,
            &output_path,
            &recipient,
            &sender.sender_public(),
        );

        assert!(matches!(result, Err(VaultError::InvalidFormat)));

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_truncated_vault_rejected() {
        let sender = Identity::generate().unwrap();
        let recipient = Identity::generate().unwrap();
        let test_dir = make_test_dir("truncated");

        let input_path = test_dir.join("test.txt");
        let vault_path = test_dir.join("test.qvault");
        let output_path = test_dir.join("test_out.txt");

        fs::write(&input_path, b"Data that will be truncated").unwrap();

        encrypt_file(
            &input_path,
            &vault_path,
            &sender,
            &recipient.recipient_public(),
        )
        .unwrap();

        // Truncate the vault file to just the header (cut off ciphertext)
        let vault_data = fs::read(&vault_path).unwrap();
        let truncated = &vault_data[..vault_data.len() / 2];
        fs::write(&vault_path, truncated).unwrap();

        let result = decrypt_file(
            &vault_path,
            &output_path,
            &recipient,
            &sender.sender_public(),
        );

        assert!(result.is_err(), "Truncated vault should fail");

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_truncated_at_chunk_boundary_rejected() {
        let sender = Identity::generate().unwrap();
        let recipient = Identity::generate().unwrap();
        let test_dir = make_test_dir("truncated_boundary");

        let input_path = test_dir.join("boundary.bin");
        let vault_path = test_dir.join("boundary.qvault");
        let output_path = test_dir.join("boundary_out.bin");

        let data = vec![0xA5; encrypt_stream::CHUNK_SIZE];
        fs::write(&input_path, &data).unwrap();

        encrypt_file(
            &input_path,
            &vault_path,
            &sender,
            &recipient.recipient_public(),
        )
        .unwrap();

        // Remove only the final authenticated EOF marker. Older stream handling
        // accepted this as a clean EOF and returned the truncated plaintext.
        let mut vault_data = fs::read(&vault_path).unwrap();
        vault_data.truncate(vault_data.len() - (4 + 12 + 20));
        fs::write(&vault_path, &vault_data).unwrap();

        let result = decrypt_file(
            &vault_path,
            &output_path,
            &recipient,
            &sender.sender_public(),
        );

        assert!(matches!(result, Err(VaultError::UnexpectedEof)));
        assert!(!output_path.exists());

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_version_mismatch_rejected() {
        let sender = Identity::generate().unwrap();
        let recipient = Identity::generate().unwrap();
        let test_dir = make_test_dir("version");

        let input_path = test_dir.join("test.txt");
        let vault_path = test_dir.join("test.qvault");
        let output_path = test_dir.join("test_out.txt");

        fs::write(&input_path, b"version test").unwrap();

        encrypt_file(
            &input_path,
            &vault_path,
            &sender,
            &recipient.recipient_public(),
        )
        .unwrap();

        // Change version bytes (bytes 4-5 after QVLT magic)
        let mut vault_data = fs::read(&vault_path).unwrap();
        vault_data[4] = 0x00;
        vault_data[5] = 0x01; // version 1 instead of 3
        fs::write(&vault_path, &vault_data).unwrap();

        let result = decrypt_file(
            &vault_path,
            &output_path,
            &recipient,
            &sender.sender_public(),
        );

        assert!(matches!(result, Err(VaultError::UnsupportedVersion)));

        let _ = fs::remove_dir_all(&test_dir);
    }

    // ───── Consistency tests ─────

    #[test]
    fn test_multiple_encryptions_produce_different_ciphertext() {
        let sender = Identity::generate().unwrap();
        let recipient = Identity::generate().unwrap();
        let test_dir = make_test_dir("nondeterministic");

        let input_path = test_dir.join("test.txt");
        let vault_path1 = test_dir.join("test1.qvault");
        let vault_path2 = test_dir.join("test2.qvault");

        fs::write(&input_path, b"Same plaintext twice").unwrap();

        encrypt_file(
            &input_path,
            &vault_path1,
            &sender,
            &recipient.recipient_public(),
        )
        .unwrap();

        encrypt_file(
            &input_path,
            &vault_path2,
            &sender,
            &recipient.recipient_public(),
        )
        .unwrap();

        let ct1 = fs::read(&vault_path1).unwrap();
        let ct2 = fs::read(&vault_path2).unwrap();

        // Same plaintext should produce different ciphertext (random ephemeral keys, salt, nonce)
        assert_ne!(
            ct1, ct2,
            "Encrypting the same file twice must produce different ciphertext"
        );

        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_self_encrypt_decrypt() {
        // Encrypt to yourself (sender == recipient)
        let identity = Identity::generate().unwrap();
        let test_dir = make_test_dir("self_encrypt");

        let input_path = test_dir.join("self.txt");
        let vault_path = test_dir.join("self.qvault");
        let output_path = test_dir.join("self_out.txt");

        fs::write(&input_path, b"Self-encrypted message").unwrap();

        encrypt_file(
            &input_path,
            &vault_path,
            &identity,
            &identity.recipient_public(),
        )
        .unwrap();

        decrypt_file(
            &vault_path,
            &output_path,
            &identity,
            &identity.sender_public(),
        )
        .unwrap();

        assert_eq!(fs::read(&output_path).unwrap(), b"Self-encrypted message");

        let _ = fs::remove_dir_all(&test_dir);
    }
}
