import os
import sys
import ctypes
import platform
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ==========================================
# CROSS-PLATFORM RESOURCE LOADER
# ==========================================

def get_library_name():
    """Returns the correct library filename based on the OS."""
    system = platform.system()
    if system == "Windows":
        return "liboqs.dll"
    elif system == "Darwin": # MacOS
        return "liboqs.dylib"
    else: # Linux
        return "liboqs.so"

def get_resource_path(filename):
    """Get absolute path to resource, works for dev and for PyInstaller."""
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, filename)

# Load the correct library for the current OS
lib_name = get_library_name()
DLL_PATH = get_resource_path(lib_name)

# ==========================================
# C-LIBRARY BINDINGS
# ==========================================

# Constants for Kyber-1024
KYBER_ALG = b"Kyber1024"
KYBER_PUB_KEY_SIZE = 1568
KYBER_PRIV_KEY_SIZE = 3168
KYBER_CIPHERTEXT_SIZE = 1568
KYBER_SHARED_SECRET_SIZE = 32

try:
    oqs_lib = ctypes.CDLL(DLL_PATH)
except OSError:
    print(f"Error: Could not load {lib_name}.")
    print(f"Ensure {lib_name} is in the same folder as this script.")
    sys.exit(1)

# Define C function signatures
oqs_lib.OQS_KEM_new.restype = ctypes.c_void_p
oqs_lib.OQS_KEM_keypair.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
oqs_lib.OQS_KEM_encaps.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
oqs_lib.OQS_KEM_decaps.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
oqs_lib.OQS_KEM_free.argtypes = [ctypes.c_void_p]

def get_kyber_keys():
    """Generates a Kyber-1024 Public/Private keypair via C library."""
    kem = oqs_lib.OQS_KEM_new(KYBER_ALG)
    
    pub_key = (ctypes.c_ubyte * KYBER_PUB_KEY_SIZE)()
    priv_key = (ctypes.c_ubyte * KYBER_PRIV_KEY_SIZE)()
    
    oqs_lib.OQS_KEM_keypair(kem, pub_key, priv_key)
    oqs_lib.OQS_KEM_free(kem)
    
    return bytes(pub_key), bytes(priv_key)

def quantum_encapsulate(pub_key_bytes):
    """Generates a shared secret and encapsulates it for the given public key."""
    kem = oqs_lib.OQS_KEM_new(KYBER_ALG)
    
    ciphertext = (ctypes.c_ubyte * KYBER_CIPHERTEXT_SIZE)()
    shared_secret = (ctypes.c_ubyte * KYBER_SHARED_SECRET_SIZE)()
    
    pub_key_ptr = (ctypes.c_ubyte * len(pub_key_bytes)).from_buffer_copy(pub_key_bytes)
    
    oqs_lib.OQS_KEM_encaps(kem, ciphertext, shared_secret, pub_key_ptr)
    oqs_lib.OQS_KEM_free(kem)
    
    return bytes(ciphertext), bytes(shared_secret)

def quantum_decapsulate(ciphertext_bytes, priv_key_bytes):
    """Unwraps the shared secret using the private key."""
    kem = oqs_lib.OQS_KEM_new(KYBER_ALG)
    
    shared_secret = (ctypes.c_ubyte * KYBER_SHARED_SECRET_SIZE)()
    
    ct_ptr = (ctypes.c_ubyte * len(ciphertext_bytes)).from_buffer_copy(ciphertext_bytes)
    sk_ptr = (ctypes.c_ubyte * len(priv_key_bytes)).from_buffer_copy(priv_key_bytes)
    
    oqs_lib.OQS_KEM_decaps(kem, shared_secret, ct_ptr, sk_ptr)
    oqs_lib.OQS_KEM_free(kem)
    
    return bytes(shared_secret)

# ==========================================
# VAULT LOGIC (ENCRYPTION & DECRYPTION)
# ==========================================

def derive_hybrid_key(shared_classic, shared_quantum):
    """Mixes both secrets using SHA3-256 to create a single AES key."""
    combined_secret = shared_classic + shared_quantum
    return HKDF(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=None,
        info=b"Quantum Vault Hybrid Mix v1"
    ).derive(combined_secret)

def lock_vault(file_path, recipient_classic_pub, recipient_quantum_pub):
    """Encrypts a file into a .qvault container."""
    
    # 1. Generate Ephemeral Classic Keys (X25519)
    ephem_classic_priv = x25519.X25519PrivateKey.generate()
    ephem_classic_pub = ephem_classic_priv.public_key().public_bytes_raw()
    
    # 2. Derive Classic Shared Secret
    recipient_c_pub_obj = x25519.X25519PublicKey.from_public_bytes(recipient_classic_pub)
    shared_classic = ephem_classic_priv.exchange(recipient_c_pub_obj)

    # 3. Derive Quantum Shared Secret (Kyber)
    quantum_ciphertext, shared_quantum = quantum_encapsulate(recipient_quantum_pub)

    # 4. Mix Keys
    aes_key = derive_hybrid_key(shared_classic, shared_quantum)

    # 5. Encrypt File Content (AES-256-GCM)
    with open(file_path, "rb") as f:
        data = f.read()
    
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    encrypted_payload = aesgcm.encrypt(nonce, data, None)

    # 6. Write Vault File
    outfile = file_path + ".qvault"
    with open(outfile, "wb") as f:
        f.write(nonce)
        f.write(ephem_classic_pub)
        f.write(quantum_ciphertext)
        f.write(encrypted_payload)

def unlock_vault(vault_path, recipient_classic_priv, recipient_quantum_priv):
    """Decrypts a .qvault container back to original file."""

    if not os.path.exists(vault_path):
        raise FileNotFoundError("Vault file not found.")

    # 1. Read Header and Payload
    with open(vault_path, "rb") as f:
        nonce = f.read(12)
        ephem_classic_pub_bytes = f.read(32)
        quantum_ciphertext = f.read(KYBER_CIPHERTEXT_SIZE)
        encrypted_payload = f.read()

    if len(encrypted_payload) == 0:
        raise ValueError("Vault payload is empty. File may be corrupted.")

    # 2. Recover Classic Shared Secret
    ephem_classic_pub = x25519.X25519PublicKey.from_public_bytes(ephem_classic_pub_bytes)
    shared_classic = recipient_classic_priv.exchange(ephem_classic_pub)

    # 3. Recover Quantum Shared Secret
    shared_quantum = quantum_decapsulate(quantum_ciphertext, recipient_quantum_priv)

    # 4. Mix Keys
    aes_key = derive_hybrid_key(shared_classic, shared_quantum)

    # 5. Decrypt
    aesgcm = AESGCM(aes_key)
    # This throws an exception if authentication fails
    decrypted_data = aesgcm.decrypt(nonce, encrypted_payload, None)
    
    # 6. Smart Filename Restoration
    # Example: image.png.qvault -> image_restored.png
    if vault_path.endswith(".qvault"):
        base = vault_path[:-7] # Remove .qvault
        root, ext = os.path.splitext(base)
        output_name = f"{root}_restored{ext}"
    else:
        output_name = vault_path + "_restored"

    # Write in Binary Mode to preserve all file types
    with open(output_name, "wb") as f:
        f.write(decrypted_data)
        
    return output_name