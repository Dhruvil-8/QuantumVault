//! Tauri Commands for QuantumVault
//!
//! These commands are exposed to the frontend via Tauri's IPC mechanism.
//! All paths are validated against user-accessible directories to prevent
//! path traversal attacks from a compromised frontend.

#![cfg(feature = "tauri")]

use std::path::PathBuf;

use quantumvault_core::{Identity, RecipientPublic, SenderPublic};

// ─── Path validation ───────────────────────────────────────────────────────

/// Directories the Tauri frontend is allowed to access.
/// We allow Desktop, Documents, Downloads, and their subdirectories.
fn allowed_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(home) = dirs::home_dir() {
        roots.push(home.join("Desktop"));
        roots.push(home.join("Documents"));
        roots.push(home.join("Downloads"));
    }
    // Also allow standard user data locations
    if let Some(data) = dirs::data_dir() {
        roots.push(data);
    }
    roots
}

/// Validate that a user-supplied path is within an allowed directory.
/// Canonicalizes the path and checks it against known safe roots.
/// For paths that don't exist yet (e.g., output files), we validate the parent.
fn validate_path(user_path: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(user_path);

    // Try to canonicalize; if the path doesn't exist yet, canonicalize its parent.
    let canonical = if path.exists() {
        std::fs::canonicalize(&path)
            .map_err(|_| "Invalid path: unable to resolve".to_string())?
    } else {
        let parent = path.parent()
            .ok_or_else(|| "Invalid path: no parent directory".to_string())?;
        if !parent.exists() {
            return Err("Invalid path: parent directory does not exist".to_string());
        }
        let canonical_parent = std::fs::canonicalize(parent)
            .map_err(|_| "Invalid path: unable to resolve parent".to_string())?;
        let file_name = path.file_name()
            .ok_or_else(|| "Invalid path: no file name".to_string())?;
        canonical_parent.join(file_name)
    };

    let roots = allowed_roots();
    if roots.iter().any(|root| {
        if let Ok(canonical_root) = std::fs::canonicalize(root) {
            canonical.starts_with(&canonical_root)
        } else {
            false
        }
    }) {
        Ok(canonical)
    } else {
        Err("Access denied: path is outside allowed directories".to_string())
    }
}

// ─── Error sanitization ────────────────────────────────────────────────────

/// Log the detailed error to stderr and return a user-friendly message.
fn sanitize_err(context: &str, err: impl std::fmt::Display) -> String {
    eprintln!("[QuantumVault Error] {}: {}", context, err);
    format!("{} failed. Check your selected paths and try again.", context)
}

// ─── Commands ──────────────────────────────────────────────────────────────

/// Generate a new cryptographic identity
///
/// Creates ML-KEM, ML-DSA, and X25519 keypairs and saves them to disk.
#[tauri::command]
pub fn generate_identity(base_dir: String) -> Result<String, String> {
    let validated = validate_path(&base_dir)?;
    let identity = Identity::generate().map_err(|e| sanitize_err("Key generation", e))?;
    identity
        .save_to(&validated)
        .map_err(|e| sanitize_err("Identity save", e))?;

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
    let input_validated = validate_path(&input)?;
    let output_validated = validate_path(&output)?;
    let sender_validated = validate_path(&sender_path)?;
    let recipient_validated = validate_path(&recipient_pub_path)?;

    let sender = Identity::load(&sender_validated)
        .map_err(|e| sanitize_err("Load sender identity", e))?;
    let recipient_pub = RecipientPublic::load(&recipient_validated)
        .map_err(|e| sanitize_err("Load recipient public key", e))?;

    quantumvault_core::encrypt_file(
        &input_validated,
        &output_validated,
        &sender,
        &recipient_pub,
    )
    .map_err(|e| sanitize_err("Encryption", e))?;

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
    let vault_validated = validate_path(&vault_path)?;
    let output_validated = validate_path(&output_path)?;
    let recipient_validated = validate_path(&recipient_path)?;
    let sender_validated = validate_path(&sender_pub_path)?;

    let recipient = Identity::load(&recipient_validated)
        .map_err(|e| sanitize_err("Load recipient identity", e))?;
    let sender_pub = SenderPublic::load(&sender_validated)
        .map_err(|e| sanitize_err("Load sender public key", e))?;

    quantumvault_core::decrypt_file(
        &vault_validated,
        &output_validated,
        &recipient,
        &sender_pub,
    )
    .map_err(|e| sanitize_err("Decryption", e))?;

    Ok("Decryption successful".to_string())
}

/// Get information about an identity
#[tauri::command]
pub fn get_identity_info(identity_path: String) -> Result<serde_json::Value, String> {
    let validated = validate_path(&identity_path)?;
    let identity = Identity::load(&validated)
        .map_err(|e| sanitize_err("Load identity", e))?;

    Ok(serde_json::json!({
        "x25519_pub": hex::encode(identity.x25519_public_bytes()),
        "ml_kem_pub_size": identity.ml_kem_ek_size(),
        "ml_dsa_pub_size": identity.ml_dsa_pk_size(),
    }))
}
