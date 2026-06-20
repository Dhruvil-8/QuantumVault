//! Vault Operations
//!
//! This module provides the high-level encrypt/decrypt operations
//! for QuantumVault files (.qvault).

use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

use crate::errors::VaultError;

mod header;
mod encrypt_stream;
mod decrypt_stream;

pub use header::{VaultHeader, QVLT_MAGIC, VAULT_VERSION};
pub use encrypt_stream::encrypt_stream;
pub use decrypt_stream::decrypt_stream;

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
    let res = encrypt_stream::encrypt_stream(
        reader,
        &mut writer,
        &master_key,
        &header.nonce_seed,
    );
    use zeroize::Zeroize;
    master_key.zeroize();

    res?;
    writer.flush()?;
    Ok(())
}

/// Decrypt a QuantumVault back to a file
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
    let output_file = File::create(output)?;

    let mut reader = BufReader::new(vault_file);
    let mut writer = BufWriter::new(output_file);

    // Read and verify header
    let (header, mut master_key) = VaultHeader::read_from(&mut reader, recipient, sender_pub)?;

    // Decrypt stream
    let res = decrypt_stream::decrypt_stream(
        &mut reader,
        &mut writer,
        &master_key,
        &header.nonce_seed,
    );
    use zeroize::Zeroize;
    master_key.zeroize();

    res?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Create identities
        let sender = Identity::generate();
        let recipient = Identity::generate();

        // Create test directory
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let test_dir = temp_dir().join(format!("qv_vault_test_{}", timestamp));
        fs::create_dir_all(&test_dir).unwrap();

        // Create test file
        let plaintext = b"Hello, quantum-resistant world! This is a test message.";
        let input_path = test_dir.join("test_input.txt");
        let vault_path = test_dir.join("test_input.txt.qvault");
        let output_path = test_dir.join("test_output.txt");

        fs::write(&input_path, plaintext).unwrap();

        // Encrypt
        encrypt_file(
            &input_path,
            &vault_path,
            &sender,
            &recipient.recipient_public(),
        ).expect("Encryption failed");

        // Verify vault file exists and is larger than input
        assert!(vault_path.exists());
        let vault_size = fs::metadata(&vault_path).unwrap().len();
        assert!(vault_size > plaintext.len() as u64);

        // Decrypt
        decrypt_file(
            &vault_path,
            &output_path,
            &recipient,
            &sender.sender_public(),
        ).expect("Decryption failed");

        // Verify output matches input
        let decrypted = fs::read(&output_path).unwrap();
        assert_eq!(decrypted, plaintext);

        // Cleanup
        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    fn test_wrong_recipient_fails() {
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let wrong_recipient = Identity::generate();

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let test_dir = temp_dir().join(format!("qv_wrong_test_{}", timestamp));
        fs::create_dir_all(&test_dir).unwrap();

        let input_path = test_dir.join("test.txt");
        let vault_path = test_dir.join("test.qvault");
        let output_path = test_dir.join("test_out.txt");

        fs::write(&input_path, b"Secret data").unwrap();

        // Encrypt to correct recipient
        encrypt_file(
            &input_path,
            &vault_path,
            &sender,
            &recipient.recipient_public(),
        ).unwrap();

        // Try to decrypt with wrong recipient
        let result = decrypt_file(
            &vault_path,
            &output_path,
            &wrong_recipient,
            &sender.sender_public(),
        );

        // Should fail (decryption error due to wrong key)
        assert!(result.is_err());

        let _ = fs::remove_dir_all(&test_dir);
    }
}
