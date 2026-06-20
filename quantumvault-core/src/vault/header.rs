//! Vault Header - Cryptographic Header for Encrypted Files
//!
//! The vault header contains:
//! - Magic bytes and version information
//! - Ephemeral X25519 public key
//! - ML-KEM ciphertext
//! - ML-DSA signature
//! - Nonce seed for AEAD

use std::io::{Read, Write};

use crate::errors::VaultError;
use crate::crypto::{
    identity::Identity,
    public::{RecipientPublic, SenderPublic},
    ml_kem::{self, MlKemEncapsulationKey, MlKemCiphertext, CIPHERTEXT_SIZE},
    ml_dsa::{self, MlDsaPublicKey, MlDsaSignature, SIGNATURE_SIZE},
    kdf,
};
use rand::rngs::OsRng;
use rand::RngCore;

/// Magic bytes identifying a QuantumVault file
pub const QVLT_MAGIC: &[u8; 4] = b"QVLT";

/// Current vault format version
pub const VAULT_VERSION: u16 = 2; // v2 uses FIPS 203/204

/// Vault header structure
pub struct VaultHeader {
    pub version: u16,
    pub flags: u16,
    pub eph_x25519_pub: [u8; 32],
    pub ml_kem_ciphertext: Vec<u8>,
    pub signature: Vec<u8>,
    pub nonce_seed: [u8; 32],
}

impl VaultHeader {
    /// Create a new vault header for encryption
    ///
    /// Returns the header and the derived master key for AEAD
    pub fn create(
        sender: &Identity,
        recipient: &RecipientPublic,
    ) -> Result<(Self, [u8; 32]), VaultError> {
        // Generate ephemeral X25519 keypair
        let eph_secret = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
        let eph_pub = x25519_dalek::PublicKey::from(&eph_secret);

        // Derive X25519 shared secret with recipient
        let recip_bytes = <[u8; 32]>::try_from(recipient.x25519_pub.as_slice())
            .map_err(|_| VaultError::InvalidFormat)?;
        let recip_x25519 = x25519_dalek::PublicKey::from(recip_bytes);
        let x_shared = eph_secret.diffie_hellman(&recip_x25519);

        // Encapsulate with ML-KEM
        let recip_ml_kem = MlKemEncapsulationKey::from_bytes(&recipient.ml_kem_pub)
            .map_err(|_| VaultError::CryptoError)?;
        let (ml_kem_shared, ct) = ml_kem::encapsulate(&recip_ml_kem);

        // Derive hybrid master key
        let master_key = kdf::derive_master_key(x_shared.as_bytes(), ml_kem_shared.as_bytes());

        // Generate nonce seed
        let mut nonce_seed = [0u8; 32];
        OsRng.fill_bytes(&mut nonce_seed);

        // Create unsigned header data for signing
        let ct_bytes = ct.as_bytes();
        let mut unsigned = Vec::new();
        write_prefix(
            &mut unsigned,
            &eph_pub.to_bytes(),
            &ct_bytes,
            &nonce_seed,
        )?;

        // Sign with ML-DSA
        let signature_obj = ml_dsa::sign(&unsigned, &sender.ml_dsa_sk);
        let signature = signature_obj.as_bytes().to_vec();

        let header = VaultHeader {
            version: VAULT_VERSION,
            flags: 0,
            eph_x25519_pub: eph_pub.to_bytes(),
            ml_kem_ciphertext: ct_bytes.to_vec(),
            signature,
            nonce_seed,
        };

        Ok((header, master_key))
    }

    /// Write header to output stream
    pub fn write_to<W: Write>(&self, mut w: W) -> Result<(), VaultError> {
        w.write_all(QVLT_MAGIC)?;
        w.write_all(&self.version.to_be_bytes())?;
        w.write_all(&self.flags.to_be_bytes())?;
        w.write_all(&self.eph_x25519_pub)?;
        w.write_all(&(self.ml_kem_ciphertext.len() as u32).to_be_bytes())?;
        w.write_all(&self.ml_kem_ciphertext)?;
        w.write_all(&(self.signature.len() as u32).to_be_bytes())?;
        w.write_all(&self.signature)?;
        w.write_all(&self.nonce_seed)?;
        Ok(())
    }

    /// Read header from input stream and verify + decrypt
    ///
    /// Returns the header and derived master key
    pub fn read_from<R: Read>(
        mut r: R,
        recipient: &Identity,
        sender: &SenderPublic,
    ) -> Result<(Self, [u8; 32]), VaultError> {
        // Read and verify magic
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)?;
        if &magic != QVLT_MAGIC {
            return Err(VaultError::InvalidFormat);
        }

        // Read version
        let version = read_u16(&mut r)?;
        if version != VAULT_VERSION {
            return Err(VaultError::UnsupportedVersion);
        }

        let _flags = read_u16(&mut r)?;

        // Read ephemeral X25519 public key
        let mut eph_pub = [0u8; 32];
        r.read_exact(&mut eph_pub)?;

        // Read ML-KEM ciphertext
        let ct_len = read_u32(&mut r)? as usize;
        if ct_len != CIPHERTEXT_SIZE {
            return Err(VaultError::InvalidFormat);
        }
        let mut ct = vec![0u8; ct_len];
        r.read_exact(&mut ct)?;

        // Read signature
        let sig_len = read_u32(&mut r)? as usize;
        if sig_len != SIGNATURE_SIZE {
            return Err(VaultError::InvalidFormat);
        }
        let mut sig = vec![0u8; sig_len];
        r.read_exact(&mut sig)?;

        // Read nonce seed
        let mut nonce_seed = [0u8; 32];
        r.read_exact(&mut nonce_seed)?;

        // Reconstruct signed data and verify signature
        let mut signed = Vec::new();
        write_prefix(&mut signed, &eph_pub, &ct, &nonce_seed)?;

        let sender_pk = MlDsaPublicKey::from_bytes(&sender.ml_dsa_pub)
            .map_err(|_| VaultError::CryptoError)?;
        let signature_obj = MlDsaSignature::from_bytes(&sig)
            .map_err(|_| VaultError::InvalidSignature)?;

        if !ml_dsa::verify(&signed, &signature_obj, &sender_pk) {
            return Err(VaultError::InvalidSignature);
        }

        // Derive X25519 shared secret
        let eph_pk = x25519_dalek::PublicKey::from(eph_pub);
        let x_shared = recipient.x25519.diffie_hellman_query(&eph_pk);

        // Decapsulate ML-KEM
        let ml_kem_ct = MlKemCiphertext::from_bytes(&ct)
            .map_err(|_| VaultError::InvalidFormat)?;
        let ml_kem_shared = ml_kem::decapsulate(&ml_kem_ct, &recipient.ml_kem_dk);

        // Derive master key
        let master_key = kdf::derive_master_key(x_shared.as_bytes(), ml_kem_shared.as_bytes());

        Ok((
            VaultHeader {
                version,
                flags: 0,
                eph_x25519_pub: eph_pub,
                ml_kem_ciphertext: ct,
                signature: sig,
                nonce_seed,
            },
            master_key,
        ))
    }
}

/// Write the prefix data that will be signed
fn write_prefix<W: Write>(
    mut w: W,
    eph: &[u8; 32],
    ct: &[u8],
    nonce: &[u8; 32],
) -> Result<(), VaultError> {
    w.write_all(QVLT_MAGIC)?;
    w.write_all(&VAULT_VERSION.to_be_bytes())?;
    w.write_all(&0u16.to_be_bytes())?; // flags
    w.write_all(eph)?;
    w.write_all(&(ct.len() as u32).to_be_bytes())?;
    w.write_all(ct)?;
    w.write_all(nonce)?;
    Ok(())
}

fn read_u16<R: Read>(r: &mut R) -> Result<u16, VaultError> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_be_bytes(b))
}

fn read_u32<R: Read>(r: &mut R) -> Result<u32, VaultError> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_header_roundtrip() {
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let recipient_pub = recipient.recipient_public();
        let sender_pub = sender.sender_public();

        // Create header
        let (header, master_key1) = VaultHeader::create(&sender, &recipient_pub).unwrap();

        // Write to buffer
        let mut buffer = Vec::new();
        header.write_to(&mut buffer).unwrap();

        // Read back
        let cursor = Cursor::new(buffer);
        let (read_header, master_key2) = VaultHeader::read_from(cursor, &recipient, &sender_pub).unwrap();

        // Verify master keys match
        assert_eq!(master_key1, master_key2);
        assert_eq!(header.version, read_header.version);
        assert_eq!(header.nonce_seed, read_header.nonce_seed);
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let sender = Identity::generate();
        let wrong_sender = Identity::generate();
        let recipient = Identity::generate();
        let recipient_pub = recipient.recipient_public();
        let wrong_sender_pub = wrong_sender.sender_public();

        // Create header with real sender
        let (header, _) = VaultHeader::create(&sender, &recipient_pub).unwrap();

        // Write to buffer
        let mut buffer = Vec::new();
        header.write_to(&mut buffer).unwrap();

        // Try to read with wrong sender's public key
        let cursor = Cursor::new(buffer);
        let result = VaultHeader::read_from(cursor, &recipient, &wrong_sender_pub);

        assert!(matches!(result, Err(VaultError::InvalidSignature)));
    }
}
