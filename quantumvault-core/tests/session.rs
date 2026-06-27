use quantumvault_core::PQSession;

#[test]
fn test_session_ratchet_roundtrip() {
    let key = [42u8; 32];
    let mut alice = PQSession::new(key);
    let mut bob = PQSession::new(key);

    let msg1 = b"Session message 1";
    let msg2 = b"Session message 2";

    // Alice encrypts msg1
    let ct1 = alice.encrypt(msg1).unwrap();
    // Bob decrypts msg1
    let pt1 = bob.decrypt(&ct1).unwrap();
    assert_eq!(pt1, msg1);

    // Alice encrypts msg2
    let ct2 = alice.encrypt(msg2).unwrap();
    // Bob decrypts msg2
    let pt2 = bob.decrypt(&ct2).unwrap();
    assert_eq!(pt2, msg2);
}
