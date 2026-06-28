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

#[test]
fn test_envelope_decryption_misuse_scenarios() {
    let alice = PQIdentity::generate().unwrap();
    let bob = PQIdentity::generate().unwrap();
    let bob_pub = PQPublicKey::from_bytes(&bob.export_public().unwrap()).unwrap();

    let ct = PQFile::encrypt(b"test data", &bob_pub).unwrap();

    // 1. Decrypt with wrong key
    let result = PQFile::decrypt_and_verify(&ct, &alice, None);
    assert!(result.is_err());

    // 2. Tampered ciphertext (flip a byte)
    let mut tampered = ct.clone();
    if tampered.len() > 10 {
        tampered[10] ^= 0xFF;
        let result = PQFile::decrypt_and_verify(&tampered, &bob, None);
        assert!(result.is_err());
    }

    // 3. Empty input (must fail, not panic)
    let result = PQFile::decrypt_and_verify(&[], &bob, None);
    assert!(result.is_err());

    // 4. Truncation at every byte boundary (must fail, not panic)
    for truncation in 0..ct.len() {
        let result = PQFile::decrypt_and_verify(&ct[..truncation], &bob, None);
        assert!(result.is_err());
    }

    // 5. Bit flip at every byte (must fail, not panic)
    for i in 0..ct.len() {
        let mut flipped = ct.clone();
        flipped[i] ^= 0x01;
        let result = PQFile::decrypt_and_verify(&flipped, &bob, None);
        assert!(result.is_err());
    }
}

#[test]
fn test_signature_bypass_resistance() {
    let alice = PQIdentity::generate().unwrap();
    let eve = PQIdentity::generate().unwrap();
    let eve_pub = PQPublicKey::from_bytes(&eve.export_public().unwrap()).unwrap();
    let bob = PQIdentity::generate().unwrap();
    let bob_pub = PQPublicKey::from_bytes(&bob.export_public().unwrap()).unwrap();

    // Signed envelope (Alice -> Bob)
    let ct = PQFile::encrypt_and_sign(b"important message", &bob_pub, &alice).unwrap();

    // 1. Verify with wrong public key (Eve instead of Alice)
    let result = PQFile::decrypt_and_verify(&ct, &bob, Some(&eve_pub));
    assert!(result.is_err());

    // 2. Verify tampered message (Alice's signature verified against tampered decrypted plaintext)
    // Note: AEAD decrypt will catch ciphertext tampering first. But if we could somehow bypass AEAD,
    // verification must still fail.
}

#[test]
fn test_signature_forwarding_fails() {
    let alice = PQIdentity::generate().unwrap();
    let alice_pub = PQPublicKey::from_bytes(&alice.export_public().unwrap()).unwrap();
    let bob = PQIdentity::generate().unwrap();
    let bob_pub = PQPublicKey::from_bytes(&bob.export_public().unwrap()).unwrap();
    let carol = PQIdentity::generate().unwrap();
    let carol_pub = PQPublicKey::from_bytes(&carol.export_public().unwrap()).unwrap();

    let msg = b"transfer 100 credits";

    // 1. Alice encrypts and signs message for Bob
    let envelope_alice_to_bob = PQFile::encrypt_and_sign(msg, &bob_pub, &alice).unwrap();

    // Extract Alice's signature from the Bob envelope
    // Header format: magic(3) + version(1) + flags(1) = 5 bytes
    let mut offset = 5;
    let kem_len = u32::from_le_bytes(envelope_alice_to_bob[offset..offset+4].try_into().unwrap()) as usize;
    offset += 4 + kem_len;
    let sig_len = u32::from_le_bytes(envelope_alice_to_bob[offset..offset+4].try_into().unwrap()) as usize;
    let signature = &envelope_alice_to_bob[offset+4..offset+4+sig_len];

    // 2. Bob attempts to replay Alice's signature to Carol
    // Encrypt msg to Carol
    let kem = quantumvault_core::kem::hybrid::encapsulate(&carol_pub).unwrap();
    let aead_ct = quantumvault_core::sym::aead::encrypt(&*kem.shared_key, msg).unwrap();

    // Assemble replayed envelope manually inserting Alice's signature (intended for Bob)
    let mut replayed = Vec::new();
    replayed.extend_from_slice(b"QVF"); // Magic
    replayed.push(0x01); // Version
    replayed.push(0x01); // Flags (has signature)
    replayed.extend_from_slice(&(kem.ciphertext.len() as u32).to_le_bytes());
    replayed.extend_from_slice(&kem.ciphertext);
    replayed.extend_from_slice(&(signature.len() as u32).to_le_bytes());
    replayed.extend_from_slice(signature);
    replayed.extend_from_slice(&(aead_ct.len() as u64).to_le_bytes());
    replayed.extend_from_slice(&aead_ct);

    // 3. Carol decrypts and tries to verify Alice's signature
    let result = PQFile::decrypt_and_verify(&replayed, &carol, Some(&alice_pub));
    
    // This must fail because Alice signed it bound to Bob's public key components, not Carol's!
    assert!(result.is_err());
}


