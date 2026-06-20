use rand::rngs::OsRng;
use x25519_dalek::{StaticSecret, PublicKey, SharedSecret};

use crate::errors::VaultError;

pub struct X25519KeyPair {
    pub(crate) secret: Option<StaticSecret>,
    pub(crate) public: PublicKey,
}

impl X25519KeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            secret: Some(secret),
            public,
        }
    }

    pub fn diffie_hellman_query(&self, peer: &PublicKey) -> Result<SharedSecret, VaultError> {
        let secret = self.secret.as_ref().ok_or(VaultError::KeyExchangeFailed)?;
        Ok(secret.diffie_hellman(peer))
    }

    /// Get the public key bytes
    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }
}