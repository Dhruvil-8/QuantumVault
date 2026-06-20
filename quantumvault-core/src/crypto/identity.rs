//! Cryptographic Identity for QuantumVault
//!
//! An identity contains all the keys needed for encryption and signing:
//! - X25519 keypair (classical hybrid layer)
//! - ML-KEM-1024 keypair (quantum-resistant encryption)
//! - ML-DSA-65 keypair (quantum-resistant signatures)

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use crate::crypto::{x25519, ml_kem, ml_dsa};
use crate::errors::VaultError;
use x25519_dalek::{StaticSecret, PublicKey};

/// A complete cryptographic identity
pub struct Identity {
    pub x25519: x25519::X25519KeyPair,
    pub ml_kem_ek: ml_kem::MlKemEncapsulationKey,
    pub ml_kem_dk: ml_kem::MlKemDecapsulationKey,
    pub ml_dsa_pk: ml_dsa::MlDsaPublicKey,
    pub ml_dsa_sk: ml_dsa::MlDsaPrivateKey,
}

impl Identity {
    /// Generate a new cryptographic identity
    pub fn generate() -> Self {
        let (ek, dk) = ml_kem::generate();
        let (pk, sk) = ml_dsa::generate();

        Self {
            x25519: x25519::X25519KeyPair::generate(),
            ml_kem_ek: ek,
            ml_kem_dk: dk,
            ml_dsa_pk: pk,
            ml_dsa_sk: sk,
        }
    }

    /// Save identity to disk
    /// 
    /// Directory structure:
    /// ```text
    /// base/
    /// ├── encryption/
    /// │   ├── x25519.pub
    /// │   ├── x25519.priv
    /// │   ├── ml_kem.pub
    /// │   └── ml_kem.priv
    /// └── signing/
    ///     ├── ml_dsa.pub
    ///     └── ml_dsa.priv
    /// ```
    pub fn save_to(&self, base: &Path) -> Result<(), VaultError> {
        let enc = base.join("encryption");
        let sig = base.join("signing");

        fs::create_dir_all(&enc)?;
        fs::create_dir_all(&sig)?;

        // Save X25519 keys
        write_file(enc.join("x25519.pub"), self.x25519.public.as_bytes())?;
        if let Some(secret) = &self.x25519.secret {
            use zeroize::Zeroize;
            let mut secret_bytes = secret.to_bytes();
            write_private_file(enc.join("x25519.priv"), &secret_bytes)?;
            secret_bytes.zeroize();
        }

        // Save ML-KEM keys (as_bytes returns arrays, convert to slices)
        let ml_kem_ek_bytes = self.ml_kem_ek.as_bytes();
        let mut ml_kem_dk_bytes = self.ml_kem_dk.as_bytes();
        write_file(enc.join("ml_kem.pub"), &ml_kem_ek_bytes)?;
        write_private_file(enc.join("ml_kem.priv"), &ml_kem_dk_bytes)?;
        use zeroize::Zeroize as _;
        ml_kem_dk_bytes.zeroize();

        // Save ML-DSA keys
        let ml_dsa_pk_bytes = self.ml_dsa_pk.as_bytes();
        let mut ml_dsa_sk_bytes = self.ml_dsa_sk.as_bytes();
        write_file(sig.join("ml_dsa.pub"), &ml_dsa_pk_bytes)?;
        write_private_file(sig.join("ml_dsa.priv"), &ml_dsa_sk_bytes)?;
        ml_dsa_sk_bytes.zeroize();

        Ok(())
    }

    /// Load identity from disk
    pub fn load(base: &Path) -> Result<Self, VaultError> {
        let enc = base.join("encryption");
        let sig = base.join("signing");

        // Load X25519
        let mut x25519_priv_bytes = read_file(enc.join("x25519.priv"))?;
        let x25519_secret = StaticSecret::from(
            <[u8; 32]>::try_from(x25519_priv_bytes.as_slice())
                .map_err(|_| VaultError::InvalidFormat)?
        );
        use zeroize::Zeroize;
        x25519_priv_bytes.zeroize();
        let x25519_public = PublicKey::from(&x25519_secret);
        let x25519_kp = x25519::X25519KeyPair {
            secret: Some(x25519_secret),
            public: x25519_public,
        };

        // Load ML-KEM
        let ml_kem_ek_bytes = read_file(enc.join("ml_kem.pub"))?;
        let mut ml_kem_dk_bytes = read_file(enc.join("ml_kem.priv"))?;
        let ml_kem_ek = ml_kem::MlKemEncapsulationKey::from_bytes(&ml_kem_ek_bytes)
            .map_err(|_| VaultError::InvalidFormat)?;
        let ml_kem_dk = ml_kem::MlKemDecapsulationKey::from_bytes(&ml_kem_dk_bytes)
            .map_err(|_| VaultError::InvalidFormat)?;
        ml_kem_dk_bytes.zeroize();

        // Load ML-DSA
        let ml_dsa_pk_bytes = read_file(sig.join("ml_dsa.pub"))?;
        let mut ml_dsa_sk_bytes = read_file(sig.join("ml_dsa.priv"))?;
        let ml_dsa_pk = ml_dsa::MlDsaPublicKey::from_bytes(&ml_dsa_pk_bytes)
            .map_err(|_| VaultError::InvalidFormat)?;
        let ml_dsa_sk = ml_dsa::MlDsaPrivateKey::from_bytes(&ml_dsa_sk_bytes)
            .map_err(|_| VaultError::InvalidFormat)?;
        ml_dsa_sk_bytes.zeroize();

        Ok(Self {
            x25519: x25519_kp,
            ml_kem_ek,
            ml_kem_dk,
            ml_dsa_pk,
            ml_dsa_sk,
        })
    }
}

fn read_file(path: impl AsRef<Path>) -> Result<Vec<u8>, VaultError> {
    fs::read(path).map_err(VaultError::Io)
}

fn write_file(path: impl AsRef<Path>, data: &[u8]) -> Result<(), VaultError> {
    let mut f = File::create(path)?;
    f.write_all(data)?;
    Ok(())
}

fn write_private_file(path: impl AsRef<Path>, data: &[u8]) -> Result<(), VaultError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        let mut f = options.open(path)?;
        f.write_all(data)?;
    }
    #[cfg(not(unix))]
    {
        let mut f = File::create(path)?;
        f.write_all(data)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_identity_generation() {
        let identity = Identity::generate();
        assert!(identity.x25519.secret.is_some());
    }

    #[test]
    fn test_identity_save_load() {
        let identity = Identity::generate();
        
        // Create unique temp directory
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let test_dir = temp_dir().join(format!("qv_test_{}", timestamp));
        
        // Save
        identity.save_to(&test_dir).expect("Failed to save identity");
        
        // Verify files exist
        assert!(test_dir.join("encryption/x25519.pub").exists());
        assert!(test_dir.join("encryption/x25519.priv").exists());
        assert!(test_dir.join("encryption/ml_kem.pub").exists());
        assert!(test_dir.join("encryption/ml_kem.priv").exists());
        assert!(test_dir.join("signing/ml_dsa.pub").exists());
        assert!(test_dir.join("signing/ml_dsa.priv").exists());
        
        // Load
        let loaded = Identity::load(&test_dir).expect("Failed to load identity");
        
        // Verify keys match
        assert_eq!(
            identity.x25519.public.as_bytes(),
            loaded.x25519.public.as_bytes()
        );
        assert_eq!(
            identity.ml_kem_ek.as_bytes(),
            loaded.ml_kem_ek.as_bytes()
        );
        assert_eq!(
            identity.ml_dsa_pk.as_bytes(),
            loaded.ml_dsa_pk.as_bytes()
        );
        
        // Cleanup
        let _ = fs::remove_dir_all(&test_dir);
    }
}