//! Tauri Commands for QuantumVault
//!
//! These commands are exposed to the frontend via Tauri's IPC mechanism.

#![cfg(feature = "tauri")]

use std::path::{Path, PathBuf};

use quantumvault_core::{Identity, RecipientPublic, SenderPublic};

/// Generate a new cryptographic identity
///
/// Creates ML-KEM, ML-DSA, and X25519 keypairs and saves them to disk.
#[tauri::command]
pub fn generate_identity(base_dir: String) -> Result<String, String> {
    let identity = Identity::generate();
    identity
        .save_to(Path::new(&base_dir))
        .map_err(|e| e.to_string())?;

    Ok("Identity generated successfully".to_string())
}

/// Encrypt a file using the sender's identity and recipient's public keys
#[tauri::command]
pub fn encrypt_file(
    input: String,
    output: String,
    sender_path: String,
    recipient_pub_path: String,
) -> Result<String, String> {
    let sender = Identity::load(Path::new(&sender_path)).map_err(|e| e.to_string())?;
    let recipient_pub =
        RecipientPublic::load(Path::new(&recipient_pub_path)).map_err(|e| e.to_string())?;

    quantumvault_core::encrypt_file(
        &PathBuf::from(input),
        &PathBuf::from(output),
        &sender,
        &recipient_pub,
    )
    .map_err(|e| e.to_string())?;

    Ok("Encryption successful".to_string())
}

/// Decrypt a vault file using the recipient's identity and sender's public key
#[tauri::command]
pub fn decrypt_file(
    vault_path: String,
    output_path: String,
    recipient_path: String,
    sender_pub_path: String,
) -> Result<String, String> {
    let recipient = Identity::load(Path::new(&recipient_path)).map_err(|e| e.to_string())?;
    let sender_pub =
        SenderPublic::load(Path::new(&sender_pub_path)).map_err(|e| e.to_string())?;

    quantumvault_core::decrypt_file(
        &PathBuf::from(vault_path),
        &PathBuf::from(output_path),
        &recipient,
        &sender_pub,
    )
    .map_err(|e| e.to_string())?;

    Ok("Decryption successful".to_string())
}

/// Get information about an identity
#[tauri::command]
pub fn get_identity_info(identity_path: String) -> Result<serde_json::Value, String> {
    let identity = Identity::load(Path::new(&identity_path)).map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "x25519_pub": hex::encode(identity.x25519.public.as_bytes()),
        "ml_kem_pub_size": identity.ml_kem_ek.as_bytes().len(),
        "ml_dsa_pub_size": identity.ml_dsa_pk.as_bytes().len(),
    }))
}