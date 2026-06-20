use rand::rngs::OsRng;
use x25519_dalek::{StaticSecret, PublicKey, SharedSecret};

pub struct X25519KeyPair {
    pub secret: Option<StaticSecret>,
    pub public: PublicKey,
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

    pub fn diffie_hellman_query(&self, peer: &PublicKey) -> SharedSecret {
        let secret = self.secret.as_ref().expect("X25519 secret missing");
        secret.diffie_hellman(peer)
    }
}