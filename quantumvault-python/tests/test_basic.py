import pytest
from quantumvault import Identity, PublicKey, encrypt, decrypt, sign, verify

def test_roundtrip():
    alice = Identity(label="alice")
    bob   = Identity(label="bob")
    msg   = b"hello post-quantum world"

    envelope  = encrypt(msg, bob.public_key, sender=alice)
    plaintext = decrypt(envelope, bob, sender_public=alice.public_key)
    assert plaintext == msg

def test_anonymous_encrypt():
    bob      = Identity()
    envelope = encrypt(b"anonymous", bob.public_key)
    result   = decrypt(envelope, bob)
    assert result == b"anonymous"

def test_sign_verify():
    alice = Identity()
    msg   = b"signed message"
    sig   = sign(msg, alice)
    verify(msg, sig, alice.public_key)  # should not raise

def test_verify_fails_on_tampered_message():
    alice = Identity()
    sig   = sign(b"original", alice)
    with pytest.raises(ValueError):
        verify(b"tampered", sig, alice.public_key)

def test_key_export_import():
    alice       = Identity(label="persistence test")
    secret_bytes = alice.export_secret()
    alice2      = Identity.from_secret_bytes(secret_bytes)
    assert alice.export_public() == alice2.export_public()

def test_wrong_recipient_fails():
    alice = Identity()
    bob   = Identity()
    carol = Identity()
    envelope = encrypt(b"for bob only", bob.public_key)
    with pytest.raises(ValueError):
        decrypt(envelope, carol)
