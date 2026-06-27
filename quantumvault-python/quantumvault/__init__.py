"""
QuantumVault — Post-Quantum Cryptography SDK

Examples
--------
>>> from quantumvault import Identity, PublicKey, encrypt, decrypt

# Generate keypairs
>>> alice = Identity(label="alice")
>>> bob   = Identity(label="bob")

# Encrypt from Alice to Bob (signed)
>>> envelope = encrypt(b"hello world", bob.public_key, sender=alice)

# Bob decrypts and verifies
>>> plaintext = decrypt(envelope, bob, sender_public=alice.public_key)
>>> plaintext
b'hello world'

# File encryption
>>> with open("secret.pdf", "rb") as f: data = f.read()
>>> envelope = encrypt(data, recipient_pub)
>>> with open("secret.pdf.qvf", "wb") as f: f.write(envelope)
"""

from quantumvault._quantumvault import (
    Identity as _Identity,
    PublicKey,
    encrypt,
    decrypt,
    sign,
    verify,
    __version__,
)


class Identity(_Identity):
    """A hybrid post-quantum keypair (X25519 + ML-KEM-1024 + ML-DSA-87).

    Parameters
    ----------
    label : str, optional
        Human-readable name stored in the key metadata.
    """

    @property
    def public_key(self) -> PublicKey:
        """Return the public key for this identity."""
        return PublicKey(self.export_public())

    def save_secret(self, path: str) -> None:
        """Write secret key bytes to file. Encrypt separately before distributing."""
        with open(path, "wb") as f:
            f.write(self.export_secret())

    @classmethod
    def load_secret(cls, path: str) -> "Identity":
        """Load identity from secret key file."""
        with open(path, "rb") as f:
            return cls.from_secret_bytes(f.read())


def encrypt_file(input_path: str, output_path: str, recipient: PublicKey,
                 sender: Identity = None) -> None:
    """Encrypt a file at `input_path` and write envelope to `output_path`."""
    with open(input_path, "rb") as f:
        data = f.read()
    envelope = encrypt(data, recipient, sender)
    with open(output_path, "wb") as f:
        f.write(envelope)


def decrypt_file(input_path: str, output_path: str, recipient: Identity,
                 sender_public: PublicKey = None) -> None:
    """Decrypt a QVF envelope at `input_path` and write plaintext to `output_path`."""
    with open(input_path, "rb") as f:
        envelope = f.read()
    plaintext = decrypt(envelope, recipient, sender_public)
    with open(output_path, "wb") as f:
        f.write(plaintext)


__all__ = [
    "Identity", "PublicKey",
    "encrypt", "decrypt", "sign", "verify",
    "encrypt_file", "decrypt_file",
    "__version__",
]
