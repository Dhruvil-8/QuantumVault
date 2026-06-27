use quantumvault_core::{PQIdentity, PQPublicKey, PQFile};

#[test]
fn test_file_encrypt_decrypt_roundtrip() {
    let alice = PQIdentity::generate().unwrap();
    let bob = PQIdentity::generate().unwrap();

    let alice_pub = PQPublicKey::from_bytes(&alice.export_public().unwrap()).unwrap();
    let bob_pub = PQPublicKey::from_bytes(&bob.export_public().unwrap()).unwrap();

    let msg = b"Top secret post-quantum payload";
    
    // Encrypt and sign (Alice -> Bob)
    let envelope = PQFile::encrypt_and_sign(msg, &bob_pub, &alice).unwrap();

    // Decrypt and verify
    let decrypted = PQFile::decrypt_and_verify(&envelope, &bob, Some(&alice_pub)).unwrap();
    assert_eq!(decrypted, msg);

    // Decrypt anonymously (no sender public key provided)
    let decrypted_anon = PQFile::decrypt_and_verify(&envelope, &bob, None).unwrap();
    assert_eq!(decrypted_anon, msg);
}

#[test]
fn test_file_decrypt_wrong_key_fails() {
    let alice = PQIdentity::generate().unwrap();
    let bob = PQIdentity::generate().unwrap();
    let carol = PQIdentity::generate().unwrap();

    let bob_pub = PQPublicKey::from_bytes(&bob.export_public().unwrap()).unwrap();

    let msg = b"Top secret";
    let envelope = PQFile::encrypt_and_sign(msg, &bob_pub, &alice).unwrap();

    // Carol tries to decrypt Bob's file
    let res = PQFile::decrypt_and_verify(&envelope, &carol, None);
    assert!(res.is_err());
}
