use hkdf::Hkdf;
use sha3::Sha3_256;
use zeroize::Zeroize;

pub fn derive_master_key(classic: &[u8], quantum: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut combined = [classic, quantum].concat();

    let hk = Hkdf::<Sha3_256>::new(None, &combined);
    hk.expand(b"QuantumVault-Hybrid-Key-v1", &mut out)
        .expect("HKDF expand failed");

    combined.zeroize();
    out
}

pub fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, crate::errors::VaultError> {
    let hk = Hkdf::<Sha3_256>::from_prk(prk)
        .map_err(|_| crate::errors::VaultError::CryptoError)?;
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out)
        .map_err(|_| crate::errors::VaultError::CryptoError)?;
    Ok(out)
}
