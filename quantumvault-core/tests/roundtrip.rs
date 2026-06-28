use quantumvault_core::{PQIdentity, PQPublicKey, KeyMeta};
use quantumvault_core::error::QVError;

#[test]
fn test_identity_generation_and_export_import() {
    let meta = KeyMeta {
        label: Some("Alice".to_string()),
        comment: Some("Test comment".to_string()),
        expires_at: Some(2051222400), // Year 2035 (future)
    };
    let identity = PQIdentity::generate_with_meta(meta).unwrap();
    
    // Export and import public key
    let pub_bytes = identity.export_public().unwrap();
    let pub_key = PQPublicKey::from_bytes(&pub_bytes).unwrap();
    
    assert_eq!(pub_key.meta.label, Some("Alice".to_string()));
    assert_eq!(pub_key.meta.comment, Some("Test comment".to_string()));
    assert_eq!(pub_key.meta.expires_at, Some(2051222400));

    // Export and import secret key
    let sec_bytes = identity.export_secret().unwrap();
    
    let identity2 = PQIdentity::from_secret_bytes(&sec_bytes).unwrap();

    assert_eq!(identity2.meta.label, Some("Alice".to_string()));
    assert_eq!(identity.export_public().unwrap(), identity2.export_public().unwrap());
}

#[test]
fn test_expired_key_rejection() {
    // Generate key with an expiry in the past (2020)
    let meta = KeyMeta {
        label: Some("Expired Identity".to_string()),
        comment: None,
        expires_at: Some(1577836800), // Year 2020 (past)
    };
    
    let identity = PQIdentity::generate_with_meta(meta).unwrap();
    let pub_bytes = identity.export_public().unwrap();
    
    // Decoding must fail with InvalidKeyFormat detailing key expiry
    let res = PQPublicKey::from_bytes(&pub_bytes);
    assert!(res.is_err());
    if let Err(QVError::InvalidKeyFormat(msg)) = res {
        assert!(msg.contains("expired"));
    } else {
        panic!("expected InvalidKeyFormat due to key expiry, got {:?}", res);
    }
}

#[test]
fn test_key_serialization_errors() {
    let identity = PQIdentity::generate().unwrap();
    let mut pub_bytes = identity.export_public().unwrap();

    // 1. Magic mismatch
    pub_bytes[0] = 0x00;
    let res = PQPublicKey::from_bytes(&pub_bytes);
    assert!(matches!(res, Err(QVError::InvalidMagic { .. })));
    pub_bytes[0] = 0x51; // restore

    // 2. Checksum corruption
    let len = pub_bytes.len();
    pub_bytes[len - 1] ^= 0xFF; // flip a bit in checksum
    let res = PQPublicKey::from_bytes(&pub_bytes);
    assert!(matches!(res, Err(QVError::InvalidKeyFormat(..))));
}

#[test]
fn test_kem_roundtrip() {
    let identity = PQIdentity::generate().unwrap();
    let pub_bytes = identity.export_public().unwrap();
    let pub_key = PQPublicKey::from_bytes(&pub_bytes).unwrap();

    // Encapsulate
    let kem_result = quantumvault_core::kem::hybrid::encapsulate(&pub_key).unwrap();
    
    // Decapsulate
    let dec_key = quantumvault_core::kem::hybrid::decapsulate(&identity, &kem_result.ciphertext).unwrap();

    assert_eq!(*kem_result.shared_key, *dec_key);
}

#[test]
fn test_sign_verify_roundtrip() {
    let identity = PQIdentity::generate().unwrap();
    let pub_bytes = identity.export_public().unwrap();
    let pub_key = PQPublicKey::from_bytes(&pub_bytes).unwrap();

    let msg = b"Hello, post-quantum world!";
    let sig = quantumvault_core::sign(&identity, msg).unwrap();
    
    // Verify
    let res = quantumvault_core::verify(&pub_key, msg, &sig);
    assert!(res.is_ok());

    // Tampered message
    let res = quantumvault_core::verify(&pub_key, b"Hello, post-quantum world.", &sig);
    assert!(res.is_err());
}
