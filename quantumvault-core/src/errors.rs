use thiserror::Error;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Invalid vault format")]
    InvalidFormat,

    #[error("Unsupported vault version")]
    UnsupportedVersion,

    #[error("Signature verification failed")]
    InvalidSignature,

    #[error("Cryptographic failure")]
    CryptoError,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Unexpected end of file")]
    UnexpectedEof,

    #[error("I/O error")]
    Io(#[from] std::io::Error),
}
