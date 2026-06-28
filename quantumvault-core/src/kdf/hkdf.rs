use crate::error::{QVError, QVResult};
use hkdf::Hkdf;
use sha3::Sha3_512;
use zeroize::Zeroizing;

/// HKDF-SHA3-512 with explicit info binding.
/// Always use a unique HKDF_INFO_* constant per usage context.
/// Returns `Zeroizing<Vec<u8>>` to ensure derived key material is erased on drop.
pub fn hkdf_sha3_512(
    ikm:    &[u8],
    salt:   Option<&[u8]>,
    info:   &[u8],
    length: usize,
) -> QVResult<Zeroizing<Vec<u8>>> {
    let hk = Hkdf::<Sha3_512>::new(salt, ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|_| QVError::Unknown("HKDF expand failed — requested length too long".into()))?;
    Ok(Zeroizing::new(okm))
}
