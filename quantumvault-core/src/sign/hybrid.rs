use crate::error::{QVError, QVResult};
use crate::keys::identity::{PQIdentity, PQPublicKey};
use fips204::traits::{Signer, Verifier};
use sha3::{Digest, Sha3_256};

/// Sign arbitrary bytes. Returns ML-DSA-87 detached signature bytes.
/// The message is pre-hashed with SHA3-256 to support large payloads.
pub fn sign(identity: &PQIdentity, message: &[u8]) -> QVResult<Vec<u8>> {
    let hash = Sha3_256::digest(message);
    let sig_bytes = identity.mldsa_secret.try_sign(&hash, &[])
        .map_err(|e: &'static str| QVError::Signing(e.to_string()))?;
    Ok(sig_bytes.to_vec())
}

/// Verify a detached signature produced by `sign`.
pub fn verify(public_key: &PQPublicKey, message: &[u8], signature: &[u8]) -> QVResult<()> {
    let hash = Sha3_256::digest(message);
    let sig_arr: [u8; 4627] = signature.try_into()
        .map_err(|_| QVError::InvalidKeyFormat("invalid signature size".into()))?;
    
    let verified = public_key.mldsa_public.verify(&hash, &sig_arr, &[]);
    if verified {
        Ok(())
    } else {
        Err(QVError::VerificationFailed)
    }
}
