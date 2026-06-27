use thiserror::Error;

#[derive(Debug, Error)]
pub enum QVError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Encapsulation failed: {0}")]
    Encapsulation(String),

    #[error("Decapsulation failed: {0}")]
    Decapsulation(String),

    #[error("Signing failed: {0}")]
    Signing(String),

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed — ciphertext is corrupt or key is wrong")]
    DecryptionFailed,

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Key version mismatch: expected {expected}, got {got}")]
    KeyVersionMismatch { expected: u8, got: u8 },

    #[error("Invalid magic header: expected {expected:?}, got {got:?}")]
    InvalidMagic { expected: [u8; 3], got: [u8; 3] },

    #[error("Serialisation error: {0}")]
    Serialisation(String),

    #[error("Deserialisation error: {0}")]
    Deserialisation(String),

    #[error("File too large: {size} bytes exceeds maximum {max} bytes")]
    FileTooLarge { size: u64, max: u64 },

    #[error("Session nonce exhausted — rekey required")]
    NonceExhausted,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

pub type QVResult<T> = Result<T, QVError>;
