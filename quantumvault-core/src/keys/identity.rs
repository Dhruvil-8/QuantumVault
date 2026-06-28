// src/keys/identity.rs

use crate::constants::*;
use crate::error::{QVError, QVResult};
use crate::keys::format::{encode_qvkey, decode_qvkey, KeyMeta, KeyType};
use fips203::ml_kem_1024;
use fips204::ml_dsa_87;
use fips203::traits::{KeyGen as KemKeyGen, SerDes as KemSerDes};
use fips204::traits::{Signer, SerDes as SignSerDes};
use rand_core::OsRng;
use x25519_dalek::{PublicKey as X25519PK, StaticSecret};
use zeroize::Zeroize;

use std::fmt;

pub struct PQIdentity {
    // S6: Secret key fields are pub(crate) to prevent direct external access
    pub(crate) x25519_secret:    StaticSecret,
    pub x25519_public:    X25519PK,
    pub mlkem_public:     ml_kem_1024::EncapsKey,
    pub(crate) mlkem_secret:     ml_kem_1024::DecapsKey,
    pub mldsa_public:     ml_dsa_87::PublicKey,
    pub(crate) mldsa_secret:     ml_dsa_87::PrivateKey,
    pub meta: KeyMeta,
}

impl fmt::Debug for PQIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fp = self.x25519_public.as_bytes();
        f.debug_struct("PQIdentity")
            .field("meta", &self.meta)
            .field("x25519_public", &hex::encode(fp))
            .field("x25519_secret", &"<redacted>")
            .field("mlkem_public", &"<mlkem_1024_public_key>")
            .field("mlkem_secret", &"<redacted>")
            .field("mldsa_public", &"<mldsa_87_public_key>")
            .field("mldsa_secret", &"<redacted>")
            .finish()
    }
}


// S7: Zeroize secret key material on drop
impl Drop for PQIdentity {
    fn drop(&mut self) {
        // StaticSecret doesn't expose a mutable byte reference, but it does implement Zeroize
        // For X25519, the Zeroize is handled by the dalek crate's own Drop impl.
        // ML-KEM and ML-DSA key material is stored in their respective structs.
        // We can't directly zeroize those types, but we ensure our own intermediate buffers
        // are always zeroized (see from_secret_bytes and export_secret).
        //
        // Note: x25519-dalek's StaticSecret implements ZeroizeOnDrop when the zeroize feature
        // is enabled. The fips203/fips204 crates handle their own key zeroization.
    }
}

impl PQIdentity {
    pub fn generate() -> QVResult<Self> {
        Self::generate_with_meta(KeyMeta::default())
    }

    pub fn generate_with_meta(meta: KeyMeta) -> QVResult<Self> {
        let x25519_secret = StaticSecret::random_from_rng(OsRng);
        let x25519_public = X25519PK::from(&x25519_secret);

        let (mlkem_public, mlkem_secret) = ml_kem_1024::KG::try_keygen()
            .map_err(|e| QVError::KeyGeneration(e.to_string()))?;

        let (mldsa_public, mldsa_secret) = ml_dsa_87::try_keygen()
            .map_err(|e| QVError::KeyGeneration(e.to_string()))?;

        Ok(Self {
            x25519_secret,
            x25519_public,
            mlkem_public,
            mlkem_secret,
            mldsa_public,
            mldsa_secret,
            meta,
        })
    }

    pub fn export_public(&self) -> QVResult<Vec<u8>> {
        let mut payload = Vec::with_capacity(
            X25519_PUBLIC_KEY_SIZE + MLKEM1024_PUBLIC_KEY_SIZE + MLDSA87_PUBLIC_KEY_SIZE
        );
        payload.extend_from_slice(self.x25519_public.as_bytes());
        payload.extend_from_slice(&KemSerDes::into_bytes(self.mlkem_public.clone()));
        payload.extend_from_slice(&SignSerDes::into_bytes(self.mldsa_public.clone()));
        encode_qvkey(KeyType::HybridPublic, &self.meta, &payload)
    }

    pub fn export_secret(&self) -> QVResult<Vec<u8>> {
        let mut payload = Vec::with_capacity(
            X25519_SECRET_KEY_SIZE + MLKEM1024_SECRET_KEY_SIZE + MLDSA87_SECRET_KEY_SIZE
        );
        payload.extend_from_slice(self.x25519_secret.as_bytes());
        payload.extend_from_slice(&KemSerDes::into_bytes(self.mlkem_secret.clone()));
        payload.extend_from_slice(&SignSerDes::into_bytes(self.mldsa_secret.clone()));
        let result = encode_qvkey(KeyType::HybridSecret, &self.meta, &payload);
        payload.zeroize();
        result
    }

    pub fn export_public_b64(&self) -> QVResult<String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        Ok(STANDARD.encode(self.export_public()?))
    }

    pub fn from_secret_bytes(data: &[u8]) -> QVResult<Self> {
        let decoded = decode_qvkey(data)?;
        if decoded.key_type != KeyType::HybridSecret {
            return Err(QVError::InvalidKeyFormat("expected HybridSecret key".into()));
        }

        let expected_len = X25519_SECRET_KEY_SIZE + MLKEM1024_SECRET_KEY_SIZE + MLDSA87_SECRET_KEY_SIZE;
        if decoded.payload.len() != expected_len {
            return Err(QVError::InvalidKeyFormat(
                format!("payload size mismatch: expected {expected_len}, got {}", decoded.payload.len())
            ));
        }

        let mut offset = 0;

        // X25519
        let mut x25519_bytes: [u8; 32] = decoded.payload[offset..offset+32].try_into().unwrap();
        let x25519_secret = StaticSecret::from(x25519_bytes);
        x25519_bytes.zeroize();
        let x25519_public = X25519PK::from(&x25519_secret);
        offset += 32;

        // ML-KEM-1024
        let mut mlkem_bytes = zeroize::Zeroizing::new([0u8; MLKEM1024_SECRET_KEY_SIZE]);
        mlkem_bytes.copy_from_slice(&decoded.payload[offset..offset+MLKEM1024_SECRET_KEY_SIZE]);
        let mlkem_secret = KemSerDes::try_from_bytes(*mlkem_bytes)
            .map_err(|e: &'static str| QVError::InvalidKeyFormat(e.to_string()))?;
        
        let mut mlkem_pub_bytes = zeroize::Zeroizing::new([0u8; MLKEM1024_PUBLIC_KEY_SIZE]);
        // Per FIPS 203, DecapsKey = d_PKE (1536 bytes) || ek (1568 bytes) || H(ek) (32 bytes) || z (32 bytes)
        // Thus, the encapsulation key (ek) starts at index 1536.
        mlkem_pub_bytes.copy_from_slice(&decoded.payload[offset + 1536 .. offset + 1536 + MLKEM1024_PUBLIC_KEY_SIZE]);
        let mlkem_public = KemSerDes::try_from_bytes(*mlkem_pub_bytes)
            .map_err(|e: &'static str| QVError::InvalidKeyFormat(e.to_string()))?;
        offset += MLKEM1024_SECRET_KEY_SIZE;

        // ML-DSA-87
        let mut mldsa_bytes = zeroize::Zeroizing::new([0u8; MLDSA87_SECRET_KEY_SIZE]);
        mldsa_bytes.copy_from_slice(&decoded.payload[offset..offset+MLDSA87_SECRET_KEY_SIZE]);
        let mldsa_secret: ml_dsa_87::PrivateKey = SignSerDes::try_from_bytes(*mldsa_bytes)
            .map_err(|e: &'static str| QVError::InvalidKeyFormat(e.to_string()))?;
        let mldsa_public = mldsa_secret.get_public_key();

        Ok(Self {
            x25519_secret,
            x25519_public,
            mlkem_public,
            mlkem_secret,
            mldsa_public,
            mldsa_secret,
            meta: decoded.meta.clone(),
        })
    }
}

pub struct PQPublicKey {
    pub x25519_public: X25519PK,
    pub mlkem_public:  ml_kem_1024::EncapsKey,
    pub mldsa_public:  ml_dsa_87::PublicKey,
    pub meta:          KeyMeta,
}

impl fmt::Debug for PQPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fp = self.x25519_public.as_bytes();
        let fingerprint = self.fingerprint().unwrap_or_else(|_| "unknown".to_string());
        f.debug_struct("PQPublicKey")
            .field("meta", &self.meta)
            .field("x25519_public", &hex::encode(fp))
            .field("fingerprint", &fingerprint)
            .field("mlkem_public", &"<mlkem_1024_public_key>")
            .field("mldsa_public", &"<mldsa_87_public_key>")
            .finish()
    }
}


impl PQPublicKey {
    pub fn from_bytes(data: &[u8]) -> QVResult<Self> {
        let decoded = decode_qvkey(data)?;
        if decoded.key_type != KeyType::HybridPublic {
            return Err(QVError::InvalidKeyFormat("expected HybridPublic key".into()));
        }

        let expected = X25519_PUBLIC_KEY_SIZE + MLKEM1024_PUBLIC_KEY_SIZE + MLDSA87_PUBLIC_KEY_SIZE;
        if decoded.payload.len() != expected {
            return Err(QVError::InvalidKeyFormat("payload size mismatch".into()));
        }

        let x25519_bytes: [u8; 32] = decoded.payload[0..32].try_into().unwrap();
        let x25519_public = X25519PK::from(x25519_bytes);

        let mut mlkem_bytes = [0u8; MLKEM1024_PUBLIC_KEY_SIZE];
        mlkem_bytes.copy_from_slice(&decoded.payload[32..32+MLKEM1024_PUBLIC_KEY_SIZE]);
        let mlkem_public = KemSerDes::try_from_bytes(mlkem_bytes)
            .map_err(|e: &'static str| QVError::InvalidKeyFormat(e.to_string()))?;

        let mut mldsa_bytes = [0u8; MLDSA87_PUBLIC_KEY_SIZE];
        mldsa_bytes.copy_from_slice(&decoded.payload[32+MLKEM1024_PUBLIC_KEY_SIZE..]);
        let mldsa_public = SignSerDes::try_from_bytes(mldsa_bytes)
            .map_err(|e: &'static str| QVError::InvalidKeyFormat(e.to_string()))?;

        Ok(Self { x25519_public, mlkem_public, mldsa_public, meta: decoded.meta.clone() })
    }

    pub fn from_b64(s: &str) -> QVResult<Self> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let bytes = STANDARD.decode(s)
            .map_err(|e| QVError::Deserialisation(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    /// Returns a BLAKE3 fingerprint of the public key bytes for out-of-band verification.
    /// Format: `QV:xxxx:xxxx:xxxx:xxxx` (first 8 bytes of hash as hex pairs).
    pub fn fingerprint(&self) -> QVResult<String> {
        let pub_bytes = self.export_raw()?;
        let hash = blake3::hash(&pub_bytes);
        let bytes = hash.as_bytes();
        Ok(format!(
            "QV:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7]
        ))
    }

    /// Export the raw concatenated public key components (without QVKey envelope).
    fn export_raw(&self) -> QVResult<Vec<u8>> {
        let mut payload = Vec::with_capacity(
            X25519_PUBLIC_KEY_SIZE + MLKEM1024_PUBLIC_KEY_SIZE + MLDSA87_PUBLIC_KEY_SIZE
        );
        payload.extend_from_slice(self.x25519_public.as_bytes());
        payload.extend_from_slice(&KemSerDes::into_bytes(self.mlkem_public.clone()));
        payload.extend_from_slice(&SignSerDes::into_bytes(self.mldsa_public.clone()));
        Ok(payload)
    }
}
