use hkdf::Hkdf;
use sha3::Sha3_256;
use zeroize::Zeroize;

/// Derive a master key from classical and quantum shared secrets using HKDF.
///
/// A random salt is required to strengthen the extract step per RFC 5869.
pub fn derive_master_key(classic: &[u8], quantum: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut combined = [classic, quantum].concat();

    let hk = Hkdf::<Sha3_256>::new(Some(salt), &combined);
    hk.expand(b"QuantumVault-Hybrid-Key-v1", &mut out)
        .expect("HKDF expand failed");

    combined.zeroize();
    out
}

pub fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, crate::errors::VaultError> {
    let hk = Hkdf::<Sha3_256>::from_prk(prk)
        .map_err(|_| crate::errors::VaultError::CryptoError)?;
    let mut out = vec![0u8; len];
    if let Err(_) = hk.expand(info, &mut out) {
        out.zeroize();
        return Err(crate::errors::VaultError::CryptoError);
    }
    Ok(out)
}
