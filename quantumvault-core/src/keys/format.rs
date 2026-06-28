// src/keys/format.rs

use crate::constants::*;
use crate::error::{QVError, QVResult};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyType {
    HybridPublic  = 0x01,
    HybridSecret  = 0x02,
    SigningPublic  = 0x03,
    SigningSecret  = 0x04,
}

impl TryFrom<u8> for KeyType {
    type Error = QVError;
    fn try_from(v: u8) -> QVResult<Self> {
        match v {
            0x01 => Ok(Self::HybridPublic),
            0x02 => Ok(Self::HybridSecret),
            0x03 => Ok(Self::SigningPublic),
            0x04 => Ok(Self::SigningSecret),
            other => Err(QVError::InvalidKeyFormat(format!("unknown KeyType byte: {other:#04x}"))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeyMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,  // Unix timestamp
}

impl KeyMeta {
    /// Returns `true` if this key has an expiry timestamp that is in the past.
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now().timestamp() > expires_at
        } else {
            false
        }
    }
}

/// Serialise key material into QVKey v1 binary format.
pub fn encode_qvkey(
    key_type: KeyType,
    meta: &KeyMeta,
    payload: &[u8],
) -> QVResult<Vec<u8>> {
    let meta_json = serde_json::to_vec(meta)
        .map_err(|e: serde_json::Error| QVError::Serialisation(e.to_string()))?;
    if meta_json.len() > u16::MAX as usize {
        return Err(QVError::Serialisation("metadata too large".into()));
    }
    let created_at = Utc::now().timestamp() as u64;

    let mut buf = Vec::with_capacity(19 + meta_json.len() + payload.len() + 32);
    buf.extend_from_slice(&QVKEY_MAGIC);
    buf.push(QVKEY_VERSION);
    buf.push(key_type as u8);
    buf.extend_from_slice(&created_at.to_le_bytes());
    buf.extend_from_slice(&(meta_json.len() as u16).to_le_bytes());
    buf.extend_from_slice(&meta_json);
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);

    // BLAKE3 checksum
    let hash = blake3::hash(&buf);
    buf.extend_from_slice(hash.as_bytes());

    Ok(buf)
}

pub struct DecodedQVKey {
    pub key_type:   KeyType,
    pub created_at: u64,
    pub meta:       KeyMeta,
    pub payload:    Vec<u8>,
}

pub fn decode_qvkey(data: &[u8]) -> QVResult<DecodedQVKey> {
    if data.len() < 19 + 32 {
        return Err(QVError::InvalidKeyFormat("buffer too short".into()));
    }

    // Magic
    let magic: [u8; 3] = data[0..3].try_into().unwrap();
    if magic != QVKEY_MAGIC {
        return Err(QVError::InvalidMagic { expected: QVKEY_MAGIC, got: magic });
    }

    // Version
    let version = data[3];
    if version != QVKEY_VERSION {
        return Err(QVError::KeyVersionMismatch { expected: QVKEY_VERSION, got: version });
    }

    let key_type = KeyType::try_from(data[4])?;
    let created_at = u64::from_le_bytes(data[5..13].try_into().unwrap());
    let meta_len = u16::from_le_bytes(data[13..15].try_into().unwrap()) as usize;

    let meta_start: usize = 15;
    let meta_end = match meta_start.checked_add(meta_len) {
        Some(end) => end,
        None => return Err(QVError::InvalidKeyFormat("overflowing metadata length".into())),
    };
    let meta_len_check = match meta_end.checked_add(4) {
        Some(end) => end,
        None => return Err(QVError::InvalidKeyFormat("overflowing metadata bounds".into())),
    };
    if data.len() < meta_len_check {
        return Err(QVError::InvalidKeyFormat("truncated at meta".into()));
    }

    let meta: KeyMeta = serde_json::from_slice(&data[meta_start..meta_end])
        .map_err(|e: serde_json::Error| QVError::Deserialisation(e.to_string()))?;

    // S3: Enforce key expiry — reject expired keys at decode time
    if meta.is_expired() {
        return Err(QVError::InvalidKeyFormat(
            "key has expired — generate a new keypair".into()
        ));
    }

    let payload_len = u32::from_le_bytes(data[meta_end..meta_end+4].try_into().unwrap()) as usize;
    const MAX_PAYLOAD_LEN: usize = 16 * 1024 * 1024; // 16MB max key payload
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(QVError::InvalidKeyFormat("payload length exceeds maximum allowed".into()));
    }
    let payload_start: usize = meta_end + 4;
    let payload_end = match payload_start.checked_add(payload_len) {
        Some(end) => end,
        None => return Err(QVError::InvalidKeyFormat("overflowing payload length".into())),
    };
    let total_len_check = match payload_end.checked_add(32) {
        Some(end) => end,
        None => return Err(QVError::InvalidKeyFormat("overflowing key bounds".into())),
    };

    if data.len() < total_len_check {
        return Err(QVError::InvalidKeyFormat("truncated at payload".into()));
    }

    // S4: Verify checksum using constant-time comparison to prevent timing side-channels
    let expected_hash = blake3::hash(&data[..payload_end]);
    let stored_hash = &data[payload_end..payload_end + 32];
    if expected_hash.as_bytes().ct_eq(stored_hash).unwrap_u8() != 1 {
        return Err(QVError::InvalidKeyFormat("checksum mismatch — key is corrupt".into()));
    }

    Ok(DecodedQVKey {
        key_type,
        created_at,
        meta,
        payload: data[payload_start..payload_end].to_vec(),
    })
}

impl Drop for DecodedQVKey {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}
